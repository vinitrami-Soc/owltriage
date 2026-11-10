"""Option 2, Phase 4: case management in TheHive 5 (REST API v1)."""
from __future__ import annotations

from typing import List

import requests

SEVERITY_TO_THEHIVE = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
TLP_AMBER = 2
PAP_AMBER = 2


def _cell(text) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(text).replace("|", "/").replace("\n", " ")


def build_case_payload(report) -> dict:
    mock = " (MOCK DATA)" if report.mock else ""
    md = [
        f"Automatically opened by **OwlTriage**{mock}.",
        "",
        "### Alert",
        f"- **Wazuh alert:** `{report.alert_id}`",
        f"- **Rule:** {report.rule_id} (level {report.rule_level}): {report.rule_description}",
        f"- **Host:** {report.agent_name} ({report.agent_ip})",
        f"- **Time:** {report.timestamp}",
    ]
    if report.file_path:
        md.append(f"- **File:** `{report.file_path}`")
    if report.username:
        md.append(f"- **User:** {report.username}")
    if report.mitre:
        md.append(f"- **MITRE ATT&CK:** {', '.join(report.mitre)}")
    md += ["", "### Threat intelligence", "",
           "| Provider | Indicator | Verdict | Score | Details |", "|---|---|---|---|---|"]
    for r in report.results:
        details = r.error or r.summary
        if r.link:
            details = f"{details} [link]({r.link})"
        md.append(f"| {r.provider} | `{_cell(r.indicator)}` | {r.verdict} | {r.score_text} | {_cell(details)} |")
    md += ["", "### Recommended actions"] + [f"- [ ] {_cell(action)}" for action in report.recommendations]

    tags = ["auto-triage", "wazuh", f"wazuh-rule:{report.rule_id}", f"severity:{report.severity}"]
    tags += [f"mitre:{technique}" for technique in report.mitre]
    return {
        "title": f"[Auto-Triage] {report.rule_description} on {report.agent_name}"[:512],
        "description": "\n".join(md),
        "severity": SEVERITY_TO_THEHIVE[report.severity],
        "tlp": TLP_AMBER,
        "pap": PAP_AMBER,
        "flag": report.severity == "critical",
        "tags": tags,
    }


def build_observable_payloads(report) -> List[dict]:
    payloads = []
    for obs in report.observables:
        intel = [r for r in report.results if r.indicator == obs.value and not (r.skipped or r.error)]
        summary = "; ".join(f"{r.provider}: {r.score_text}" for r in intel) or "not enriched"
        payloads.append({
            "dataType": "ip" if obs.kind == "ip" else "hash",
            "data": obs.value,
            "message": f"From alert field {obs.field}. {summary}",
            "tlp": TLP_AMBER,
            "pap": PAP_AMBER,
            "ioc": any(r.flagged for r in intel),
            "sighted": True,
            "tags": ["auto-triage"],
        })
    return payloads


class TheHiveClient:
    def __init__(self, base_url: str, api_key: str, session: requests.Session,
                 timeout: float = 15.0, verify_tls: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session
        self.timeout = timeout
        self.verify_tls = verify_tls

    def _post(self, path: str, payload: dict):
        response = self.session.post(f"{self.base_url}{path}", json=payload, timeout=self.timeout,
                                     headers={"Authorization": f"Bearer {self.api_key}"},
                                     verify=self.verify_tls)
        response.raise_for_status()
        return response.json()

    def create_case(self, payload: dict) -> dict:
        return self._post("/api/v1/case", payload)

    def add_observable(self, case_id: str, payload: dict):
        return self._post(f"/api/v1/case/{case_id}/observable", payload)
