"""The owl's summary: what happened and what to do next, in plain sentences.

Analysts read this first; the findings table underneath is the evidence.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .defense import BlockRule
from .detectors import AnalysisResult, Finding
from .utils import SEVERITY_RANK, clean, max_severity

HUMAN = {
    "SQL_INJECTION": "SQL injection", "XSS": "XSS", "PATH_TRAVERSAL": "path traversal",
    "COMMAND_INJECTION": "command injection", "LOG4SHELL": "Log4Shell", "SHELLSHOCK": "Shellshock",
    "SENSITIVE_FILE_PROBE": "secret-file probing", "SCANNER_USER_AGENT": "vulnerability scanning",
    "BAD_IP_MATCH": "known-bad IP", "BRUTE_FORCE": "brute force", "C2_INDICATOR": "C2 server",
    "BASE64_PAYLOAD": "encoded payload", "SUSPICIOUS_COMMAND": "malicious command",
}
# Order in which an IP's activity is described: the attack itself first, the noise last.
PRIORITY = ["SQL_INJECTION", "COMMAND_INJECTION", "LOG4SHELL", "SHELLSHOCK", "PATH_TRAVERSAL", "XSS",
            "SUSPICIOUS_COMMAND", "BRUTE_FORCE", "SENSITIVE_FILE_PROBE", "BASE64_PAYLOAD", "SCANNER_USER_AGENT"]
HOST_CRITICAL = {"RANSOMWARE_PRECURSOR", "CREDENTIAL_DUMPING"}
PERSISTENCE = {"PERSISTENCE", "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT"}
MAX_STORIES, MAX_STEPS = 9, 6


@dataclass
class Story:
    severity: str
    who: str
    text: str
    mitre: List[str] = field(default_factory=list)


@dataclass
class Summary:
    stories: List[Story] = field(default_factory=list)
    more: int = 0
    steps: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"stories": [s.__dict__ for s in self.stories], "more": self.more, "next_steps": self.steps}


def _ip_story(ip: str, findings: List[Finding]) -> Story:
    worst = max_severity(f.severity for f in findings)
    by_rule: Dict[str, Finding] = {}
    for f in sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity]):
        by_rule.setdefault(f.rule, f)
    mitre = sorted({t for f in findings for t in f.mitre})
    listed = " (on your blocklist / threat feed)" if "BAD_IP_MATCH" in by_rule else ""
    compromise = by_rule.get("COMPROMISE_SUSPECTED") or by_rule.get("LOGIN_FROM_BAD_IP")
    if compromise:
        how = by_rule["BRUTE_FORCE"].title if "BRUTE_FORCE" in by_rule else "Known-bad IP"
        where = f" on {compromise.host}" if compromise.host else ""
        return Story(worst, ip, f"{how}, then logged in as '{clean(compromise.user, 30)}'{where}{listed}", mitre)
    if set(by_rule) <= {"C2_INDICATOR", "BAD_IP_MATCH"}:
        hosts = sorted({f.host for f in findings if f.host})
        seen = f" from {', '.join(hosts)}" if hosts else ""
        return Story(worst, ip, f"Payload / C2 server referenced in decoded commands{seen}{listed}", mitre)
    rules = sorted((r for r in by_rule if r != "BAD_IP_MATCH"),
                   key=lambda r: PRIORITY.index(r) if r in PRIORITY else len(PRIORITY))
    names = [by_rule[r].title if r == "BRUTE_FORCE" else HUMAN.get(r, r.replace("_", " ").lower()) for r in rules]
    text = ", ".join(names[:3])
    return Story(worst, ip, f"{text[:1].upper()}{text[1:]}{listed}", mitre)


def summarize(result: AnalysisResult, block_rules: Sequence[BlockRule], script_name: Optional[str] = None) -> Summary:
    summary = Summary()
    by_ip: Dict[str, List[Finding]] = OrderedDict()
    for f in result.findings:
        if f.ip:
            by_ip.setdefault(f.ip, []).append(f)

    stories: List[Story] = []
    for ip, findings in by_ip.items():
        if SEVERITY_RANK[max_severity(f.severity for f in findings)] >= SEVERITY_RANK["medium"]:
            stories.append(_ip_story(ip, findings))
    # Host-level events with no attacker IP (process creation, Windows events): critical ones get
    # their own line, the rest are folded into one line per host so the summary stays short.
    per_host: Dict[str, List[Finding]] = OrderedDict()
    for f in result.findings:
        if f.ip or SEVERITY_RANK[f.severity] < SEVERITY_RANK["high"]:
            continue
        host = f.host or f.source or "-"
        if f.severity == "critical":
            stories.append(Story(f.severity, host, f.title, list(f.mitre)))
        elif f.title not in {x.title for x in per_host.get(host, [])}:
            per_host.setdefault(host, []).append(f)
    for host, findings in per_host.items():
        titles = [f.title for f in findings]
        extra = f" (+{len(titles) - 3} more)" if len(titles) > 3 else ""
        stories.append(Story("high", host, "; ".join(titles[:3]) + extra, sorted({t for f in findings for t in f.mitre})))
    stories.sort(key=lambda s: -SEVERITY_RANK[s.severity])
    summary.stories, summary.more = stories[:MAX_STORIES], max(0, len(stories) - MAX_STORIES)

    steps: List[str] = []
    accounts = OrderedDict()
    for f in result.findings:
        if f.rule in ("COMPROMISE_SUSPECTED", "LOGIN_FROM_BAD_IP") and f.user:
            accounts[f"{clean(f.user, 30)}" + (f" ({f.host})" if f.host else "")] = None
    if accounts:
        steps.append(f"Reset passwords and end active sessions for: {', '.join(accounts)}")
    hot_hosts = OrderedDict()
    for f in result.findings:
        if f.rule in HOST_CRITICAL or (f.severity == "critical" and f.rule == "SUSPICIOUS_COMMAND"):
            hot_hosts[f.host or f.source or "-"] = None
    if hot_hosts:
        steps.append(f"Isolate and collect memory/disk before cleaning: {', '.join(hot_hosts)}")
    if block_rules:
        inbound = sum(r.direction == "inbound" for r in block_rules)
        outbound = len(block_rules) - inbound
        detail = f"{inbound} attacker IP(s) inbound" + (f", {outbound} C2 outbound" if outbound else "")
        steps.append(f"Review, then run {script_name or 'block_ips.sh'}: {detail}")
    persistence = OrderedDict()
    for f in result.findings:
        if f.rule in PERSISTENCE and SEVERITY_RANK[f.severity] >= SEVERITY_RANK["medium"]:
            persistence[f"{f.title.lower()}" + (f" on {f.host}" if f.host else "")] = None
    if persistence:
        steps.append("Hunt down persistence: " + "; ".join(list(persistence)[:3]))
    if any(f.rule_id == "win-log-cleared" for f in result.findings):
        steps.append("Event logs were cleared: pull copies from your SIEM / EDR for the missing period")
    if any(row["verdict"] in ("MALICIOUS", "SUSPICIOUS") for row in result.ip_verdicts()):
        steps.append("Share iocs.stix.json with your TIP (MISP/OpenCTI); open attack_layer.json in ATT&CK Navigator")
    summary.steps = steps[:MAX_STEPS]
    return summary
