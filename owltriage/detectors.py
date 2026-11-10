"""Detection engine: turns `LogEvent`s from any source into ATT&CK-mapped `Finding`s.

What fires is decided by the YAML rules in owltriage/rules/ (see rules.py):
web / command / line / event rules are regexes and field matches; the six
correlation rules below are stateful and implemented here, tuned from YAML:

  auth-brute-force               BRUTE_FORCE           N failed logins per IP inside a time window
  auth-success-after-brute-force COMPROMISE_SUSPECTED  login succeeds from that IP
  auth-success-from-bad-ip       LOGIN_FROM_BAD_IP     login succeeds from a blocklisted IP
  blocklist-match                BAD_IP_MATCH          IP on bad_ips.txt or a threat feed
  encoded-payload                BASE64_PAYLOAD        base64 / PowerShell -enc that decodes to text
  hidden-ip-in-payload           C2_INDICATOR          IP address inside a decoded payload
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from .intel import BadIPList
from .log_parser import LogEvent, extract_ips
from .rules import Rule, RuleSet, load_rules, render_template
from .sources import detect_format, iter_events
from .timeutil import iso_utc
from .utils import SEVERITY_RANK, clean, max_severity, severity_rank, verdict_for
from .windows import SourceError

SERVICE_LABEL = {"ssh": "SSH", "rdp": "RDP", "network": "Windows network logon", "interactive": "Windows logon",
                 "windows": "Windows logon", "cached": "Windows cached logon", "unlock": "Windows unlock",
                 "kerberos": "Kerberos"}


@dataclass
class Finding:
    rule: str  # category name, e.g. SQL_INJECTION (groups findings, used as block reason)
    severity: str
    title: str
    ip: Optional[str] = None
    detail: str = ""
    source: Optional[str] = None
    line_no: Optional[int] = None
    evidence: str = ""
    block: Optional[str] = None  # "inbound" | "outbound": firewall rule wanted for `ip`
    count: int = 1
    rule_id: str = ""
    mitre: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None  # first occurrence, ISO 8601 UTC when parseable
    user: Optional[str] = None
    host: Optional[str] = None

    @property
    def location(self) -> str:
        if self.source and self.line_no:
            return f"{self.source}:{self.line_no}"
        return self.source or "-"


BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_ONLY = re.compile(r"[0-9a-fA-F]+")


def _bytes_to_text(raw: bytes) -> Optional[str]:
    """UTF-8, or UTF-16LE (what PowerShell -EncodedCommand uses: every other byte is 0)."""
    half = len(raw) // 2
    if len(raw) >= 8 and len(raw) % 2 == 0 and raw[1::2].count(0) >= 0.9 * half:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def decode_base64_blobs(text: str, min_printable: float = 0.95) -> List[Tuple[str, str]]:
    """Return (encoded, decoded) pairs for base64 blobs in `text` that decode to readable text.

    Hashes, key fingerprints and random tokens decode to binary garbage, so the
    "mostly printable" check filters them out.
    """
    results: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for match in BASE64_CANDIDATE.finditer(text[:65_536]):
        token = match.group(0)
        if token in seen or HEX_ONLY.fullmatch(token):
            continue
        seen.add(token)
        body = token.rstrip("=")
        if len(body) % 4 == 1:  # impossible length for base64
            continue
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _bytes_to_text(raw)
        if decoded is None or len(decoded.strip()) < 8:
            continue
        printable = sum(ch.isprintable() or ch in "\t\r\n" for ch in decoded)
        if printable / len(decoded) >= min_printable:
            results.append((token, decoded))
    return results


class FindingCollector:
    """De-duplicates findings: the same rule/IP firing 50 times becomes one row with count=50."""

    def __init__(self) -> None:
        self._items: Dict[tuple, Finding] = {}

    def add(self, finding: Finding, key_extra: str = "") -> None:
        key = (finding.rule_id or finding.rule, finding.title, finding.ip, key_extra)
        existing = self._items.get(key)
        if existing:
            existing.count += finding.count
        else:
            self._items[key] = finding

    def __len__(self) -> int:
        return len(self._items)

    def sorted(self) -> List[Finding]:
        return sorted(self._items.values(),
                      key=lambda f: (-SEVERITY_RANK[f.severity], f.rule, f.ip or "", f.title))


@dataclass
class AnalysisResult:
    files: List[str] = field(default_factory=list)
    lines_scanned: int = 0
    events_by_kind: Counter = field(default_factory=Counter)
    log_types: Counter = field(default_factory=Counter)
    ip_lines: Counter = field(default_factory=Counter)  # ip -> number of events it appears in
    first_seen: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    failed_by_ip: Counter = field(default_factory=Counter)
    accepted_by_ip: Counter = field(default_factory=Counter)
    failed_usernames: Counter = field(default_factory=Counter)
    accepted_usernames: Counter = field(default_factory=Counter)
    findings: List[Finding] = field(default_factory=list)
    blocklist_size: int = 0
    rules_loaded: int = 0
    warnings: List[str] = field(default_factory=list)

    def severity_counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)

    def technique_counts(self) -> Counter:
        counts: Counter = Counter()
        for finding in self.findings:
            for technique in finding.mitre:
                counts[technique] += finding.count
        return counts

    def ip_verdicts(self) -> List[dict]:
        """One row per IP: activity counters plus a CLEAN/REVIEW/SUSPICIOUS/MALICIOUS verdict."""
        by_ip: Dict[str, List[Finding]] = defaultdict(list)
        for finding in self.findings:
            if finding.ip:
                by_ip[finding.ip].append(finding)
        rows = []
        for ip in set(self.ip_lines) | set(by_ip):
            found = by_ip.get(ip, [])
            worst = max_severity(f.severity for f in found)
            rows.append({
                "ip": ip,
                "lines": self.ip_lines.get(ip, 0),
                "failed_logins": self.failed_by_ip.get(ip, 0),
                "accepted_logins": self.accepted_by_ip.get(ip, 0),
                "max_severity": worst,
                "verdict": verdict_for(worst),
                "reasons": sorted({f.rule for f in found}),
                "mitre": sorted({t for f in found for t in f.mitre}),
            })
        rows.sort(key=lambda r: (-severity_rank(r["max_severity"]), -r["lines"], r["ip"]))
        return rows


class Analyzer:
    """Streaming analyzer: `feed()` events one at a time, then call `finish()`."""

    def __init__(self, bad_ips: Optional[BadIPList] = None, brute_threshold: Optional[int] = None,
                 ruleset: Optional[RuleSet] = None, window_seconds: Optional[int] = None) -> None:
        self.rules = ruleset if ruleset is not None else load_rules()
        self.bad_ips = bad_ips if bad_ips is not None else BadIPList()
        self.web_rules = self.rules.enabled("web")
        self.command_rules = self.rules.enabled("command")
        self.line_rules = self.rules.enabled("line")
        self.event_rules = self.rules.enabled("event")
        self.brute = self.rules.correlation("auth-brute-force")
        self.compromise = self.rules.correlation("auth-success-after-brute-force")
        self.bad_login = self.rules.correlation("auth-success-from-bad-ip")
        self.blocklist_rule = self.rules.correlation("blocklist-match")
        self.encoded = self.rules.correlation("encoded-payload")
        self.hidden_ip = self.rules.correlation("hidden-ip-in-payload")

        brute = self.brute
        self.threshold = max(1, int(brute_threshold if brute_threshold is not None
                                    else (brute.param("threshold", 5) if brute else 5)))
        window = window_seconds if window_seconds is not None else (brute.param("window_seconds", 600) if brute else 0)
        self.window = max(0, int(window or 0))
        self.spray_min = int(brute.param("spraying_min_users", 3)) if brute else 3

        self.result = AnalysisResult(blocklist_size=len(self.bad_ips),
                                     rules_loaded=len(self.rules.enabled()))
        self._findings = FindingCollector()
        self._fail_times: Dict[str, deque] = defaultdict(deque)
        self._fail_users: Dict[str, Set[str]] = defaultdict(set)
        self._fail_services: Dict[str, Counter] = defaultdict(Counter)
        self._brute_hits: Dict[str, dict] = {}
        self._outbound: Set[str] = set()
        self._inbound: Set[str] = set()

    # -- input ---------------------------------------------------------------
    def scan_file(self, path, year: Optional[int] = None,
                  on_progress: Optional[Callable[[ScanProgress], None]] = None,
                  file_no: int = 1, files: int = 1, done_bytes: int = 0, total_bytes: int = 0) -> None:
        self.result.files.append(str(path))
        size = Path(path).stat().st_size if on_progress else 0
        total = max(total_bytes or size, 1)
        # Bytes per event for formats whose events don't map 1:1 to text lines (rough, only for the bar).
        per_event = {"evtx": 900, "windows-xml": 1100}.get(detect_format(path), 0) if on_progress else 0
        seen_bytes, count = 0, 0

        def report(final: bool = False) -> None:
            estimate = size if final else min(seen_bytes, size * 0.98)
            on_progress(ScanProgress(Path(path).name, file_no, files, self.result.lines_scanned,
                                     len(self._findings), min(1.0, (done_bytes + estimate) / total)))

        try:
            for event in iter_events(path, year=year):
                self.feed(event)
                if on_progress:
                    count += 1
                    seen_bytes += per_event or len(event.raw) + 1
                    if count % 256 == 0:
                        report()
        except SourceError as exc:
            self.result.warnings.append(str(exc))
        if on_progress:
            report(final=True)

    def feed(self, event: LogEvent) -> None:
        result = self.result
        result.lines_scanned += 1
        result.events_by_kind[event.kind] += 1
        result.log_types["web" if event.kind == "http_request" else event.log_type] += 1
        for ip in event.ips:
            result.ip_lines[ip] += 1
            result.first_seen.setdefault(ip, (event.source, event.line_no))
        if event.ip:
            (self._outbound if event.direction == "outbound" else self._inbound).add(event.ip)

        if event.kind == "auth_failure":
            self._on_failed_login(event)
        elif event.kind == "auth_success":
            self._on_successful_login(event)
        elif event.kind == "http_request":
            self._check_web(event)
        if event.command:
            self._check_command(event.command, event)
        if event.log_type == "text" and event.kind != "http_request":
            self._check_lines(event)
        if event.event_id is not None:
            self._check_events(event)
        self._check_encoded(event)

    def finish(self) -> AnalysisResult:
        self._check_blocklist()
        self._report_brute_force()
        self.result.findings = self._findings.sorted()
        return self.result

    # -- helpers -------------------------------------------------------------
    def _finding(self, rule: Rule, event: Optional[LogEvent], title: Optional[str] = None, *,
                 ip: Optional[str] = None, detail: str = "", severity: Optional[str] = None,
                 mitre: Optional[List[str]] = None, block: Optional[str] = "rule", evidence: Optional[str] = None,
                 key_extra: str = "") -> None:
        if block == "rule":
            block = rule.block
        when = None
        if event is not None:
            when = iso_utc(event.epoch) or event.timestamp
        self._findings.add(Finding(
            rule.name, severity or rule.severity, title or rule.title, ip=ip, detail=detail,
            source=event.source if event else None, line_no=event.line_no if event else None,
            evidence=event.raw if evidence is None and event is not None else (evidence or ""),
            block=block if ip else None, rule_id=rule.id, mitre=list(rule.mitre if mitre is None else mitre),
            timestamp=when, user=event.user if event else None, host=event.host if event else None),
            key_extra=key_extra)

    # -- authentication --------------------------------------------------------
    def _recent_failures(self, ip: str, now: Optional[float]) -> int:
        times = self._fail_times[ip]
        if self.window and now is not None:
            while times and times[0] is not None and times[0] < now - self.window:
                times.popleft()
        return len(times)

    def _on_failed_login(self, event: LogEvent) -> None:
        ip = event.ip
        user = event.user if event.user else "<empty>"
        self.result.failed_by_ip[ip] += event.repeat
        self.result.failed_usernames[user] += event.repeat
        self._fail_users[ip].add(user)
        self._fail_services[ip][event.service or "ssh"] += event.repeat
        times = self._fail_times[ip]
        times.extend([event.epoch] * event.repeat)
        if not self.window and len(times) > self.threshold:  # whole-file counting: no need to keep them all
            while len(times) > self.threshold:
                times.popleft()
        recent = self._recent_failures(ip, event.epoch)
        if self.brute and recent >= self.threshold:
            hit = self._brute_hits.setdefault(ip, {"event": event, "peak": 0})
            hit["peak"] = max(hit["peak"], recent)

    def _on_successful_login(self, event: LogEvent) -> None:
        ip = event.ip
        self.result.accepted_by_ip[ip] += 1
        if event.user:
            self.result.accepted_usernames[event.user] += 1
        user = clean(event.user, 40)
        service = SERVICE_LABEL.get(event.service or "", event.service or "login")

        recent = self._recent_failures(ip, event.epoch)
        if self.compromise and recent >= self.threshold:
            within = f" within {self.window // 60} min" if self.window else ""
            self._finding(self.compromise, event, ip=ip,
                          detail=f"{service}: user '{user}' logged in after {recent} failed attempts{within}")
        listed = self.bad_ips.lookup(ip)
        if self.bad_login and listed:
            self._finding(self.bad_login, event, ip=ip, detail=f"{service}: user '{user}'; {clean(listed, 80)}")

    def _report_brute_force(self) -> None:
        if not self.brute:
            return
        for ip, hit in self._brute_hits.items():
            users = sorted(self._fail_users[ip])
            spraying = len(users) >= self.spray_min
            service_key = self._fail_services[ip].most_common(1)[0][0]
            service = SERVICE_LABEL.get(service_key, service_key.upper())
            title = f"{service} {'password spraying' if spraying else 'brute force'}"
            shown = ", ".join(clean(u, 24) for u in users[:6]) + (" …" if len(users) > 6 else "")
            within = f" within {self.window // 60} min" if self.window else ""
            total = self.result.failed_by_ip[ip]
            counted = f"{hit['peak']} failed logins{within} ({total} total)" if self.window else \
                f"{total} failed logins"
            detail = f"{counted} against {len(users)} account(s): {shown}"
            mitre = self.brute.param("mitre_spraying", self.brute.mitre) if spraying else self.brute.mitre
            self._finding(self.brute, hit["event"], title, ip=ip, detail=detail, mitre=list(mitre))

    # -- blocklist / threat feeds ------------------------------------------------
    def _check_blocklist(self) -> None:
        if not self.blocklist_rule or not len(self.bad_ips):
            return
        for ip, lines in self.result.ip_lines.items():
            listed = self.bad_ips.lookup(ip)
            if not listed:
                continue
            source, line_no = self.result.first_seen[ip]
            outbound_only = ip in self._outbound and ip not in self._inbound
            direction = "outbound" if outbound_only else self.blocklist_rule.block
            where = "contacted by this host; " if outbound_only else ""
            self._findings.add(Finding(
                self.blocklist_rule.name, self.blocklist_rule.severity, self.blocklist_rule.title, ip=ip,
                detail=f"{where}{clean(listed, 80)}; seen in {lines} event(s)", source=source, line_no=line_no,
                block=direction, rule_id=self.blocklist_rule.id, mitre=list(self.blocklist_rule.mitre)))

    # -- regex / event rules -----------------------------------------------------------
    def _check_web(self, event: LogEvent) -> None:
        path = event.path or ""
        for rule in self.web_rules:
            match = rule.search_web(path, event.user_agent, event.referrer)
            if match:
                detail = clean(event.user_agent, 90) if rule.fields == ["user_agent"] else \
                    f"{event.method} {clean(path, 110)}"
                self._finding(rule, event, rule.format_title(match), ip=event.ip, detail=detail)

    def _check_command(self, command: str, event: LogEvent, decoded_from: str = "") -> List[Rule]:
        matched = []
        for rule in self.command_rules:
            match = rule.search(command)
            if match:
                matched.append(rule)
                prefix = f"decoded from {decoded_from}: " if decoded_from else ""
                who = f" (user {clean(event.user, 30)})" if event.user else ""
                self._finding(rule, event, rule.format_title(match), ip=event.ip,
                              detail=f"{prefix}{clean(command, 110)}{who}", key_extra=command[:200])
        return matched

    def _check_lines(self, event: LogEvent) -> None:
        for rule in self.line_rules:
            match = rule.search(event.raw)
            if match:
                self._finding(rule, event, rule.format_title(match), ip=event.ip,
                              detail=clean(event.raw, 140), key_extra=event.raw[:200])

    def _check_events(self, event: LogEvent) -> None:
        for rule in self.event_rules:
            if rule.matches_record(event.event_id, event.provider, event.channel, event.fields):
                detail = render_template(rule.detail, event.fields) if rule.detail else clean(event.raw, 140)
                ip = event.fields.get(rule.ip_field) if rule.ip_field else None
                self._finding(rule, event, ip=ip or None, detail=f"[{event.event_id}] {detail}",
                              key_extra=detail[:200])

    # -- encoded payloads ----------------------------------------------------------
    def _check_encoded(self, event: LogEvent) -> None:
        if not self.encoded and not self.hidden_ip:
            return
        texts = [event.command] if event.log_type == "windows" else [event.raw, event.path]
        seen: Set[str] = set()
        for text in texts:
            if not text:
                continue
            for token, decoded in decode_base64_blobs(text):
                if decoded in seen:
                    continue
                seen.add(decoded)
                commands = self._check_command(decoded, event, decoded_from="base64")
                if self.encoded:
                    rule = self.encoded
                    self._finding(
                        rule, event,
                        rule.param("title_command", rule.title) if commands else rule.title,
                        ip=event.ip, detail=f"decodes to: {clean(decoded, 110)}", evidence=token,
                        severity=rule.param("severity_command", rule.severity) if commands else rule.severity,
                        mitre=list(rule.param("mitre_command", rule.mitre) if commands else rule.mitre),
                        block=rule.block if commands else None, key_extra=decoded[:200])
                for hidden in extract_ips(decoded):
                    self._outbound.add(hidden)
                    if self.hidden_ip:
                        listed = self.bad_ips.lookup(hidden)
                        note = f"; also on blocklist: {clean(listed, 60)}" if listed else ""
                        self._finding(self.hidden_ip, event, ip=hidden, evidence=token,
                                      detail=f"found inside decoded base64{note}")


@dataclass
class ScanProgress:
    file: str
    file_no: int
    files: int
    events: int
    findings: int
    fraction: float  # 0..1 of all bytes (estimated for binary/XML formats)


def analyze(paths: Iterable, bad_ips: Optional[BadIPList] = None, brute_threshold: Optional[int] = None,
            ruleset: Optional[RuleSet] = None, window_seconds: Optional[int] = None,
            year: Optional[int] = None,
            on_progress: Optional[Callable[[ScanProgress], None]] = None) -> AnalysisResult:
    analyzer = Analyzer(bad_ips, brute_threshold, ruleset, window_seconds)
    paths = list(paths)
    sizes = [Path(p).stat().st_size for p in paths] if on_progress else [0] * len(paths)
    done = 0
    for number, (path, size) in enumerate(zip(paths, sizes), 1):
        analyzer.scan_file(path, year, on_progress, number, len(paths), done, sum(sizes))
        done += size
    return analyzer.finish()
