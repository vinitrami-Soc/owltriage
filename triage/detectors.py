"""Option 1, Phase 2: offline analysis.

Turns parsed `LogEvent`s into `Finding`s:

  BAD_IP_MATCH          IP is on the local blocklist (bad_ips.txt)
  SSH_BRUTE_FORCE       >= N failed SSH logins from one IP (brute force / password spraying)
  COMPROMISE_SUSPECTED  successful SSH login from an IP that was brute-forcing
  LOGIN_FROM_BAD_IP     successful SSH login from a blocklisted IP
  SQL_INJECTION, XSS, PATH_TRAVERSAL   attack signatures in web requests
  SCANNER_USER_AGENT    offensive tool in the User-Agent (sqlmap, nikto, ...)
  BASE64_PAYLOAD        base64 blob that decodes to readable text (high if it is a command)
  C2_INDICATOR          IP address hidden inside a decoded payload (likely C2 / payload host)
"""
from __future__ import annotations

import base64
import binascii
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .intel import BadIPList
from .log_parser import LogEvent, extract_ips, iter_events
from .utils import SEVERITY_RANK, clean, max_severity, severity_rank, verdict_for


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    ip: Optional[str] = None
    detail: str = ""
    source: Optional[str] = None
    line_no: Optional[int] = None
    evidence: str = ""
    block: Optional[str] = None  # "inbound" | "outbound": firewall rule wanted for `ip`
    count: int = 1

    @property
    def location(self) -> str:
        if self.source and self.line_no:
            return f"{self.source}:{self.line_no}"
        return self.source or "-"


@dataclass(frozen=True)
class Signature:
    rule: str
    severity: str
    title: str
    pattern: "re.Pattern[str]"


_I = re.IGNORECASE
WEB_SIGNATURES = (
    Signature("SQL_INJECTION", "high", "SQLi: UNION-based",
              re.compile(r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b", _I)),
    Signature("SQL_INJECTION", "high", "SQLi: boolean tautology",  # ' OR '1'='1, AND 1=1
              re.compile(r"\b(?:or|and)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b", _I)),
    Signature("SQL_INJECTION", "high", "SQLi: stacked query",
              re.compile(r";\s*(?:(?:drop|truncate|alter)\s+table|delete\s+from|insert\s+into|exec(?:ute)?\s)", _I)),
    Signature("SQL_INJECTION", "high", "SQLi: time-based blind",
              re.compile(r"\b(?:sleep|pg_sleep|benchmark)\s*\(\s*\d|\bwaitfor\s+delay\b", _I)),
    Signature("SQL_INJECTION", "medium", "SQLi: schema enumeration",
              re.compile(r"\binformation_schema\b|\bsysobjects\b", _I)),
    Signature("XSS", "medium", "XSS: script injection",
              re.compile(r"<\s*script\b|javascript\s*:|\bon(?:error|load|mouseover)\s*=", _I)),
    Signature("PATH_TRAVERSAL", "high", "Path traversal / LFI",
              re.compile(r"(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow)\b|\bwin\.ini\b", _I)),
)

SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|zgrab|nuclei|hydra|acunetix|feroxbuster", _I)

BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
SUSPICIOUS_COMMAND = re.compile(
    r"/bin/(?:ba)?sh\b|\bbash\s+-i\b|/dev/(?:tcp|udp)/|\bnc(?:at)?\b.*\s-e\s"
    r"|\b(?:wget|curl)\b.*https?://|\|\s*(?:ba)?sh\b|\bpowershell\b|\bIEX\b"
    r"|\bInvoke-(?:Expression|WebRequest)\b|\bchmod\s+\+x\b|\bpython[23]?\s+-c\b"
    r"|\bperl\s+-e\b|\bmkfifo\b|\bcrontab\b",
    _I,
)


def decode_base64_blobs(text: str, min_printable: float = 0.95) -> List[Tuple[str, str]]:
    """Return (encoded, decoded) pairs for base64 blobs in `text` that decode to readable text.

    Hashes, key fingerprints and random tokens decode to binary garbage, so the
    "mostly printable UTF-8" check filters them out.
    """
    results: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for match in BASE64_CANDIDATE.finditer(text):
        token = match.group(0)
        if token in seen or HEX_ONLY.fullmatch(token):
            continue
        seen.add(token)
        body = token.rstrip("=")
        if len(body) % 4 == 1:  # impossible length for base64
            continue
        try:
            decoded = base64.b64decode(body + "=" * (-len(body) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if len(decoded.strip()) < 8:
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
        key = (finding.rule, finding.title, finding.ip, key_extra)
        existing = self._items.get(key)
        if existing:
            existing.count += finding.count
        else:
            self._items[key] = finding

    def sorted(self) -> List[Finding]:
        return sorted(self._items.values(),
                      key=lambda f: (-SEVERITY_RANK[f.severity], f.rule, f.ip or ""))


@dataclass
class AnalysisResult:
    files: List[str] = field(default_factory=list)
    lines_scanned: int = 0
    events_by_kind: Counter = field(default_factory=Counter)
    ip_lines: Counter = field(default_factory=Counter)  # ip -> number of lines it appears in
    first_seen: Dict[str, Tuple[str, int]] = field(default_factory=dict)
    failed_by_ip: Counter = field(default_factory=Counter)
    accepted_by_ip: Counter = field(default_factory=Counter)
    failed_usernames: Counter = field(default_factory=Counter)
    accepted_usernames: Counter = field(default_factory=Counter)
    findings: List[Finding] = field(default_factory=list)
    blocklist_size: int = 0

    def severity_counts(self) -> Counter:
        return Counter(f.severity for f in self.findings)

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
            })
        rows.sort(key=lambda r: (-severity_rank(r["max_severity"]), -r["lines"], r["ip"]))
        return rows


class Analyzer:
    """Streaming analyzer: `feed()` events one at a time, then call `finish()`."""

    def __init__(self, bad_ips: Optional[BadIPList] = None, brute_threshold: int = 5) -> None:
        self.bad_ips = bad_ips if bad_ips is not None else BadIPList()
        self.brute_threshold = max(1, brute_threshold)
        self.result = AnalysisResult(blocklist_size=len(self.bad_ips))
        self._findings = FindingCollector()
        self._failed_users: Dict[str, Set[str]] = defaultdict(set)
        self._first_failure: Dict[str, LogEvent] = {}

    # -- input ---------------------------------------------------------------
    def scan_file(self, path) -> None:
        self.result.files.append(str(path))
        for event in iter_events(path):
            self.feed(event)

    def feed(self, event: LogEvent) -> None:
        result = self.result
        result.lines_scanned += 1
        result.events_by_kind[event.kind] += 1
        for ip in event.ips:
            result.ip_lines[ip] += 1
            result.first_seen.setdefault(ip, (event.source, event.line_no))

        if event.kind == "ssh_failed":
            self._on_failed_login(event)
        elif event.kind == "ssh_accepted":
            self._on_accepted_login(event)
        elif event.kind == "http_request":
            self._check_web_request(event)
        self._check_base64(event)

    def finish(self) -> AnalysisResult:
        self._check_blocklist()
        self._check_brute_force()
        self.result.findings = self._findings.sorted()
        return self.result

    # -- SSH -----------------------------------------------------------------
    def _on_failed_login(self, event: LogEvent) -> None:
        user = event.user if event.user else "<empty>"
        self.result.failed_by_ip[event.ip] += event.repeat
        self.result.failed_usernames[user] += event.repeat
        self._failed_users[event.ip].add(user)
        self._first_failure.setdefault(event.ip, event)

    def _on_accepted_login(self, event: LogEvent) -> None:
        self.result.accepted_by_ip[event.ip] += 1
        if event.user:
            self.result.accepted_usernames[event.user] += 1
        user = clean(event.user, 40)

        prior_failures = self.result.failed_by_ip.get(event.ip, 0)
        if prior_failures >= self.brute_threshold:
            self._findings.add(Finding(
                "COMPROMISE_SUSPECTED", "critical", "Successful SSH login after brute force",
                ip=event.ip, detail=f"user '{user}' logged in after {prior_failures} failed attempts",
                source=event.source, line_no=event.line_no, evidence=event.raw, block="inbound"))

        listed = self.bad_ips.lookup(event.ip)
        if listed:
            self._findings.add(Finding(
                "LOGIN_FROM_BAD_IP", "critical", "Successful SSH login from blocklisted IP",
                ip=event.ip, detail=f"user '{user}'; blocklist: {listed}",
                source=event.source, line_no=event.line_no, evidence=event.raw, block="inbound"))

    def _check_brute_force(self) -> None:
        for ip, failures in self.result.failed_by_ip.items():
            if failures < self.brute_threshold:
                continue
            users = sorted(self._failed_users[ip])
            first = self._first_failure[ip]
            shown = ", ".join(clean(u, 24) for u in users[:6]) + (" …" if len(users) > 6 else "")
            self._findings.add(Finding(
                "SSH_BRUTE_FORCE", "high",
                "SSH password spraying" if len(users) >= 3 else "SSH brute force",
                ip=ip, detail=f"{failures} failed logins against {len(users)} account(s): {shown}",
                source=first.source, line_no=first.line_no, evidence=first.raw, block="inbound"))

    # -- Blocklist -----------------------------------------------------------
    def _check_blocklist(self) -> None:
        for ip, lines in self.result.ip_lines.items():
            listed = self.bad_ips.lookup(ip)
            if not listed:
                continue
            source, line_no = self.result.first_seen[ip]
            self._findings.add(Finding(
                "BAD_IP_MATCH", "high", "IP on local blocklist", ip=ip,
                detail=f"{clean(listed, 80)}; seen in {lines} line(s)",
                source=source, line_no=line_no, block="inbound"))

    # -- Web -----------------------------------------------------------------
    def _check_web_request(self, event: LogEvent) -> None:
        path = event.path or ""
        variants = [path]
        if "+" in path:
            variants.append(path.replace("+", " "))  # '+' means space in query strings
        if event.user_agent:
            variants.append(event.user_agent)

        for signature in WEB_SIGNATURES:
            if any(signature.pattern.search(text) for text in variants):
                self._findings.add(Finding(
                    signature.rule, signature.severity, signature.title, ip=event.ip,
                    detail=f"{event.method} {clean(path, 110)}", source=event.source,
                    line_no=event.line_no, evidence=event.raw, block="inbound"))

        tool = SCANNER_UA.search(event.user_agent or "")
        if tool:
            self._findings.add(Finding(
                "SCANNER_USER_AGENT", "medium", f"Offensive tool user-agent: {tool.group(0).lower()}",
                ip=event.ip, detail=clean(event.user_agent, 90), source=event.source,
                line_no=event.line_no, evidence=event.raw, block="inbound"))

    # -- Encoded payloads ----------------------------------------------------
    def _check_base64(self, event: LogEvent) -> None:
        texts = [event.raw] + ([event.path] if event.path else [])
        seen: Set[str] = set()
        for text in texts:
            for token, decoded in decode_base64_blobs(text):
                if decoded in seen:
                    continue
                seen.add(decoded)
                malicious = bool(SUSPICIOUS_COMMAND.search(decoded))
                self._findings.add(Finding(
                    "BASE64_PAYLOAD", "high" if malicious else "low",
                    "Encoded shell command (base64)" if malicious else "Base64 data in log",
                    ip=event.ip, detail=f"decodes to: {clean(decoded, 110)}",
                    source=event.source, line_no=event.line_no, evidence=token,
                    block="inbound" if malicious and event.ip else None), key_extra=decoded)

                for hidden_ip in extract_ips(decoded):
                    listed = self.bad_ips.lookup(hidden_ip)
                    note = f"; also on blocklist: {clean(listed, 60)}" if listed else ""
                    self._findings.add(Finding(
                        "C2_INDICATOR", "high", "IP hidden in encoded payload (possible C2)",
                        ip=hidden_ip, detail=f"found inside decoded base64{note}",
                        source=event.source, line_no=event.line_no, evidence=token,
                        block="outbound"))


def analyze(paths: Iterable, bad_ips: Optional[BadIPList] = None, brute_threshold: int = 5) -> AnalysisResult:
    analyzer = Analyzer(bad_ips, brute_threshold)
    for path in paths:
        analyzer.scan_file(path)
    return analyzer.finish()
