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


# Discord rejects the whole message (HTTP 400) if any embed limit is exceeded,
# which would silently drop the alert, so every piece is budgeted.
DISCORD_EMBED_TOTAL = 6000
DISCORD_MAX_FIELDS = 25


def _field(name: str, value: str, inline: bool = False, limit: int = 1024) -> dict:
    return {"name": _trim(name, 256), "value": _trim(value or "-", limit), "inline": inline}


def _embed_size(embed: dict) -> int:
    return (len(embed["title"]) + len(embed["description"]) + len(embed["footer"]["text"])
            + sum(len(f["name"]) + len(f["value"]) for f in embed["fields"]))


def build_discord_payload(report) -> dict:
    sev = report.severity
    head = [
        _field("Severity", f"{EMOJI[sev]} **{sev.upper()}**", inline=True),
        _field("Wazuh rule", f"{_code(_trim(report.rule_id, 60))} · level {report.rule_level}", inline=True),
        _field("Host", f"{report.agent_name} ({report.agent_ip})", inline=True, limit=256),
    ]
    if report.file_path:
        head.append(_field("File", _code(_trim(report.file_path, 500))))
    intel = []
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
        intel.append(_field(f"{result.provider} · {result.kind.upper()} {_short(result.indicator)}", value))
    actions = _field("Recommended actions", "\n".join(f"• {r}" for r in report.recommendations))

    embed = {
        "title": _trim(f"{EMOJI[sev]} {sev.upper()}: {report.rule_description}", 256),
        "description": _trim(f"Wazuh alert {_code(_trim(report.alert_id, 100))} at {report.timestamp}", 400),
        "color": COLORS[sev],
        "fields": head + intel + [actions],
        "footer": {"text": "OwlTriage" + (" · MOCK DATA" if report.mock else "")},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    hidden = 0
    while intel and (_embed_size(embed) > DISCORD_EMBED_TOTAL - 80 or len(embed["fields"]) > DISCORD_MAX_FIELDS):
        intel.pop()
        hidden += 1
        embed["fields"] = head + intel + [actions]
    if hidden:
        embed["description"] += f"\n… {hidden} more intel result(s) not shown; see the TheHive case."
    # allowed_mentions: alert text is attacker-influenced; never let it ping @everyone.
    return {"username": "Auto-Triage", "embeds": [embed], "allowed_mentions": {"parse": []}}


def _slack(text: str) -> str:
    """Slack mrkdwn escaping (also neutralizes <!channel>-style mentions)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _plain(text: str) -> str:
    """For plain_text blocks: Slack does not unescape &lt; there, so swap the brackets instead."""
    return str(text).replace("<", "‹").replace(">", "›")


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
                                    "text": _trim(f"{EMOJI[sev]} {sev.upper()}: {_plain(report.rule_description)}", 150)}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": _trim(f"*Host*\n{_slack(report.agent_name)} ({_slack(report.agent_ip)})", 2000)},
            {"type": "mrkdwn", "text": _trim(f"*Wazuh rule*\n{_slack(report.rule_id)} · level {report.rule_level}", 2000)},
        ]},
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": _trim("\n".join(intel_lines) or "No enrichment results", 3000)}},
        {"type": "section", "text": {"type": "mrkdwn", "text": _trim(
            "*Recommended actions*\n" + "\n".join(f"• {_slack(r)}" for r in report.recommendations), 3000)}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": _trim(
            f"Alert {_slack(report.alert_id)} · OwlTriage" + (" · MOCK DATA" if report.mock else ""), 300)}]},
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
