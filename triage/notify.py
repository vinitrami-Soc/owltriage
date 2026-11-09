"""Option 2, Phase 3: ChatOps notifications (Discord / Slack incoming webhooks)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Tuple

import requests

COLORS = {"critical": 0x8B0000, "high": 0xE74C3C, "medium": 0xF39C12, "low": 0x2ECC71, "info": 0x95A5A6}
EMOJI = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟢", "info": "ℹ️"}


def _trim(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _code(text: str) -> str:
    """Inline-code a value without letting backticks in it break the formatting."""
    return f"`{str(text).replace('`', chr(39))}`"


def _short(indicator: str) -> str:
    return indicator if len(indicator) <= 20 else f"{indicator[:12]}…{indicator[-6:]}"


def build_discord_payload(report) -> dict:
    sev = report.severity
    fields = [
        {"name": "Severity", "value": f"{EMOJI[sev]} **{sev.upper()}**", "inline": True},
        {"name": "Wazuh rule", "value": f"{_code(report.rule_id)} · level {report.rule_level}", "inline": True},
        {"name": "Host", "value": f"{report.agent_name} ({report.agent_ip})", "inline": True},
    ]
    if report.file_path:
        fields.append({"name": "File", "value": _code(report.file_path), "inline": False})
    for result in report.results:
        if result.skipped:
            continue
        value = f"**{result.verdict}** · {result.score_text}"
        if result.error:
            value += f"\n{result.error}"
        elif result.summary:
            value += f"\n{result.summary}"
        if result.link:
            value += f"\n[Open in {result.provider}]({result.link})"
        fields.append({"name": _trim(f"{result.provider} · {result.kind.upper()} {_short(result.indicator)}", 256),
                       "value": _trim(value, 1024), "inline": False})
    fields.append({"name": "Recommended actions",
                   "value": _trim("\n".join(f"• {r}" for r in report.recommendations), 1024), "inline": False})

    embed = {
        "title": _trim(f"{EMOJI[sev]} {sev.upper()}: {report.rule_description}", 256),
        "description": f"Wazuh alert {_code(report.alert_id)} at {report.timestamp}",
        "color": COLORS[sev],
        "fields": fields[:25],
        "footer": {"text": "Blue Team Auto-Triage" + (" · MOCK DATA" if report.mock else "")},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    # allowed_mentions: alert text is attacker-influenced; never let it ping @everyone.
    return {"username": "Auto-Triage", "embeds": [embed], "allowed_mentions": {"parse": []}}


def _slack(text: str) -> str:
    """Slack mrkdwn escaping (also neutralizes <!channel>-style mentions)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_slack_payload(report) -> dict:
    sev = report.severity
    intel_lines = []
    for result in report.results:
        if result.skipped:
            continue
        line = f"*{result.provider}* · `{_slack(_short(result.indicator))}` → *{result.verdict}* ({result.score_text})"
        if result.link:
            line += f" <{result.link}|view>"
        intel_lines.append(line)
    blocks = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": _trim(f"{EMOJI[sev]} {sev.upper()}: {report.rule_description}", 150)}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Host*\n{_slack(report.agent_name)} ({_slack(report.agent_ip)})"},
            {"type": "mrkdwn", "text": f"*Wazuh rule*\n{_slack(report.rule_id)} · level {report.rule_level}"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": _trim("\n".join(intel_lines) or "No enrichment results", 3000)}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _trim(
            "*Recommended actions*\n" + "\n".join(f"• {_slack(r)}" for r in report.recommendations), 3000)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": _trim(
            f"Alert {_slack(report.alert_id)} · Blue Team Auto-Triage" + (" · MOCK DATA" if report.mock else ""), 300)}]},
    ]
    return {"text": _trim(f"{sev.upper()}: {_slack(report.rule_description)}", 300), "blocks": blocks}


def send_webhook(session: requests.Session, url: str, payload: dict, timeout: float = 10.0) -> Tuple[bool, str]:
    """POST the payload. Errors never echo the URL: a webhook URL is itself a secret."""
    try:
        response = session.post(url, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        return False, f"network error ({type(exc).__name__})"
    if 200 <= response.status_code < 300:
        return True, f"HTTP {response.status_code}"
    if response.status_code == 429:
        return False, "HTTP 429: rate limited, retry later"
    return False, f"HTTP {response.status_code}"
