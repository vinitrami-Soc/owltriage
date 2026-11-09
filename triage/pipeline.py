"""Option 2: the API-driven pipeline ("master orchestrator").

    Wazuh alert JSON
      -> extract IOCs (attacker IP, file hash)
      -> enrich: VirusTotal + AbuseIPDB
      -> verdict + recommendations
      -> Discord / Slack webhook        (only when a score crosses the threshold)
      -> TheHive case with observables  (only when a score crosses the threshold)
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Tuple

import requests

from . import __version__
from .cases import TheHiveClient, build_case_payload, build_observable_payloads
from .config import Settings
from .defense import BlockRule
from .enrichment import AbuseIPDBClient, IntelResult, VirusTotalClient, load_mock_responses
from .log_parser import extract_ips, normalize_ip
from .notify import build_discord_payload, build_slack_payload, send_webhook
from .utils import SEVERITY_RANK, clean, rel

HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
IP_FIELDS = ("data.srcip", "data.src_ip", "data.source.ip", "data.win.eventdata.ipAddress", "data.dstip")
# Same file, strongest hash first: one VirusTotal lookup instead of three (free tier = 4/min).
SYSCHECK_HASHES = ("syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after")
OTHER_HASH_FIELDS = ("data.sha256", "data.sha1", "data.md5", "data.hash", "data.file_hash")
USER_FIELDS = ("data.srcuser", "data.dstuser", "syscheck.uname_after")
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def _dig(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


@dataclass
class Observable:
    kind: str  # "ip" | "hash"
    value: str
    field: str  # where in the alert it came from


def load_alerts(path) -> List[dict]:
    """Accept a single alert object, a JSON list, or Wazuh's alerts.json (one JSON per line)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    raise ValueError("alert file must hold a JSON object, a list of objects, or NDJSON")


def why_not_enrich(ip: str) -> Optional[str]:
    """Reason an IP should NOT be sent to external threat-intel APIs, or None."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or addr.is_link_local:
        return "special-purpose address"
    if any(addr.version == net.version and addr in net for net in INTERNAL_NETWORKS):
        return "internal address, not sent to external APIs"
    return None


def extract_observables(alert: dict) -> Tuple[List[Observable], List[Tuple[str, str]]]:
    found: List[Observable] = []
    skipped: List[Tuple[str, str]] = []
    seen = set()
    agent_ip = normalize_ip(str(_dig(alert, "agent.ip") or ""))

    def add_ip(raw: Any, source: str) -> None:
        ip = normalize_ip(str(raw))
        if not ip or ip in seen:
            return
        seen.add(ip)
        if ip == agent_ip:
            skipped.append((ip, "the monitored host itself"))
            return
        reason = why_not_enrich(ip)
        if reason:
            skipped.append((ip, reason))
        else:
            found.append(Observable("ip", ip, source))

    def add_hashes(raw: Any, source: str) -> bool:
        added = False
        for value in HASH_RE.findall(str(raw)):
            value = value.lower()
            if value not in seen:
                seen.add(value)
                found.append(Observable("hash", value, source))
                added = True
        return added

    for name in IP_FIELDS:
        value = _dig(alert, name)
        if value:
            add_ip(value, name)
    for name in SYSCHECK_HASHES:
        value = _dig(alert, name)
        if value and add_hashes(value, name):
            break
    for name in OTHER_HASH_FIELDS:
        value = _dig(alert, name)
        if value:
            add_hashes(value, name)

    full_log = str(alert.get("full_log") or "")
    for ip in extract_ips(full_log):
        add_ip(ip, "full_log")
    if not any(o.kind == "hash" for o in found):
        add_hashes(full_log, "full_log")
    return found, skipped


@dataclass
class TriageReport:
    alert_id: str
    timestamp: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_name: str
    agent_ip: str
    file_path: Optional[str] = None
    username: Optional[str] = None
    mitre: List[str] = field(default_factory=list)
    observables: List[Observable] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)
    results: List[IntelResult] = field(default_factory=list)
    severity: str = "low"
    flagged: bool = False
    recommendations: List[str] = field(default_factory=list)
    block_rules: List[BlockRule] = field(default_factory=list)
    actions: List[Tuple[str, str, str]] = field(default_factory=list)  # (action, status, detail)
    mock: bool = False

    @classmethod
    def from_alert(cls, alert: dict) -> "TriageReport":
        def text(path: str, default: str = "-", limit: int = 200) -> str:
            value = _dig(alert, path)
            return clean(value, limit) if value not in (None, "") else default

        try:
            level = int(_dig(alert, "rule.level") or 0)
        except (TypeError, ValueError):
            level = 0
        username = next((text(p) for p in USER_FIELDS if _dig(alert, p)), None)
        mitre = _dig(alert, "rule.mitre.id") or []
        return cls(
            alert_id=text("id", "unknown", 80),
            timestamp=text("timestamp"),
            rule_id=text("rule.id", "?", 20),
            rule_level=level,
            rule_description=text("rule.description", "Wazuh alert"),
            agent_name=text("agent.name", "unknown-host", 80),
            agent_ip=text("agent.ip", "?", 64),
            file_path=text("syscheck.path", None) if _dig(alert, "syscheck.path") else None,
            username=username,
            mitre=[clean(m, 20) for m in mitre if isinstance(m, str)],
        )

    @property
    def slug(self) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "_", self.alert_id)[:60] or "alert"


def assess(results: List[IntelResult], vt_threshold: int) -> Tuple[str, bool]:
    """Overall severity from the enrichment scores. Returns (severity, escalate?)."""
    usable = [r for r in results if r.found and not r.error]
    vt_hit = any(r.flagged for r in usable if r.provider == "VirusTotal")
    abuse_hit = any(r.flagged for r in usable if r.provider == "AbuseIPDB")
    top_vt = max((r.score or 0 for r in usable if r.provider == "VirusTotal"), default=0)

    if (vt_hit and abuse_hit) or top_vt >= 4 * max(vt_threshold, 1):
        return "critical", True
    if vt_hit or abuse_hit:
        return "high", True
    if any((r.score or 0) > 0 for r in usable):
        return "medium", False
    return "low", False


def recommend(report: TriageReport) -> List[str]:
    actions: List[str] = []
    bad_ips = list(dict.fromkeys(r.indicator for r in report.results if r.flagged and r.kind == "ip"))
    bad_hashes = list(dict.fromkeys(r.indicator for r in report.results if r.flagged and r.kind == "hash"))

    for ip in bad_ips:
        rule = BlockRule(ip, "inbound", ["threat-intel"])
        report.block_rules.append(rule)
        actions.append(f"Block {ip} at the firewall: {rule.command()}")
    for value in bad_hashes:
        where = report.file_path or "the file"
        actions.append(f"Quarantine {where} on {report.agent_name} and sweep all endpoints for hash {value[:16]}…")
    if SEVERITY_RANK[report.severity] >= SEVERITY_RANK["high"]:
        actions.append(f"Isolate {report.agent_name} ({report.agent_ip}) and preserve memory/disk for forensics")
        if report.username:
            actions.append(f"Reset credentials for '{report.username}' and review its recent sessions")
    if not actions:
        if report.severity == "medium":
            actions.append("Weak threat-intel signal: review manually before closing")
        else:
            actions.append("No threat-intel hits: confirm the change was expected, then close as benign")
    return actions


class TriagePipeline:
    def __init__(self, settings: Settings, *, mock: bool = False, dry_run: bool = False,
                 notify: bool = True, create_case: bool = True, out_dir: Path = Path("output"),
                 session: Optional[requests.Session] = None) -> None:
        self.settings = settings
        self.mock = mock
        self.dry_run = dry_run
        self.notify_enabled = notify
        self.case_enabled = create_case
        self.out_dir = Path(out_dir)
        self.session = session or requests.Session()
        if hasattr(self.session, "headers"):
            self.session.headers["User-Agent"] = f"blue-team-auto-triage/{__version__}"

        mock_data = load_mock_responses() if mock else None
        common = dict(session=self.session, timeout=settings.timeout, mock_data=mock_data)
        self.vt = (VirusTotalClient(settings.vt_api_key, settings.vt_threshold,
                                    requests_per_minute=settings.vt_requests_per_minute, **common)
                   if mock or settings.vt_api_key else None)
        self.abuse = (AbuseIPDBClient(settings.abuseipdb_api_key, settings.abuseipdb_threshold, **common)
                      if mock or settings.abuseipdb_api_key else None)

    # -- enrichment ----------------------------------------------------------
    def enrich(self, obs: Observable) -> List[IntelResult]:
        results = []
        if self.vt:
            results.append(self.vt.lookup(obs.kind, obs.value))
        else:
            results.append(IntelResult("VirusTotal", obs.value, obs.kind, skipped=True,
                                       error="VT_API_KEY not set (try --mock)"))
        if obs.kind == "ip":
            if self.abuse:
                results.append(self.abuse.check(obs.value))
            else:
                results.append(IntelResult("AbuseIPDB", obs.value, "ip", skipped=True,
                                           error="ABUSEIPDB_API_KEY not set (optional)"))
        return results

    def run(self, alert: dict) -> TriageReport:
        report = TriageReport.from_alert(alert)
        report.mock = self.mock
        report.observables, report.skipped = extract_observables(alert)
        for obs in report.observables:
            report.results.extend(self.enrich(obs))
        report.severity, report.flagged = assess(report.results, self.settings.vt_threshold)
        report.recommendations = recommend(report)
        self._notify(report)
        self._open_case(report)
        return report

    # -- outputs -------------------------------------------------------------
    def _save(self, name: str, payload: Any) -> Path:
        folder = self.out_dir / "dry_run"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def _gate(self, report: TriageReport, action: str, enabled: bool, flag: str) -> bool:
        if not enabled:
            report.actions.append((action, "skipped", f"disabled with {flag}"))
            return False
        if not report.flagged:
            report.actions.append((action, "not needed",
                                   f"no score above threshold (VT > {self.settings.vt_threshold} "
                                   f"or AbuseIPDB >= {self.settings.abuseipdb_threshold}%)"))
            return False
        return True

    def _notify(self, report: TriageReport) -> None:
        if not self._gate(report, "Chat notification", self.notify_enabled, "--no-notify"):
            return
        targets = (("Discord", self.settings.discord_webhook_url, build_discord_payload),
                   ("Slack", self.settings.slack_webhook_url, build_slack_payload))
        for name, url, build in targets:
            payload = build(report)
            if self.dry_run:
                path = self._save(f"{name.lower()}_{report.slug}.json", payload)
                report.actions.append((f"{name} webhook", "dry-run", f"payload saved to {rel(path)}"))
            elif not url:
                report.actions.append((f"{name} webhook", "skipped", f"{name.upper()}_WEBHOOK_URL not set"))
            else:
                ok, detail = send_webhook(self.session, url, payload, self.settings.timeout)
                report.actions.append((f"{name} webhook", "sent" if ok else "failed", detail))

    def _open_case(self, report: TriageReport) -> None:
        if not self._gate(report, "TheHive case", self.case_enabled, "--no-case"):
            return
        case_payload = build_case_payload(report)
        observables = build_observable_payloads(report)
        if self.dry_run:
            path = self._save(f"thehive_{report.slug}.json", {"case": case_payload, "observables": observables})
            report.actions.append(("TheHive case", "dry-run", f"payload saved to {rel(path)}"))
            return
        if not (self.settings.thehive_url and self.settings.thehive_api_key):
            report.actions.append(("TheHive case", "skipped", "THEHIVE_URL / THEHIVE_API_KEY not set"))
            return

        client = TheHiveClient(self.settings.thehive_url, self.settings.thehive_api_key, self.session,
                               self.settings.timeout, self.settings.thehive_verify_tls)
        try:
            case = client.create_case(case_payload)
        except requests.RequestException as exc:
            report.actions.append(("TheHive case", "failed", _describe(exc)))
            return
        case_id, number = case.get("_id", "?"), case.get("number", "?")
        failed = 0
        for payload in observables:
            try:
                client.add_observable(case_id, payload)
            except requests.RequestException:
                failed += 1
        detail = f"case #{number} ({case_id}), {len(observables) - failed}/{len(observables)} observables added"
        report.actions.append(("TheHive case", "created", detail))


def _describe(exc: requests.RequestException) -> str:
    response = getattr(exc, "response", None)
    if response is not None:
        return f"HTTP {response.status_code}"
    return f"network error ({type(exc).__name__})"
