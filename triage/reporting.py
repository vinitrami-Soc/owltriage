"""Phase 3: output and reporting (colored terminal output + report files).

Every value that came from a log or an alert is wrapped in `Text(clean(...))`
before printing, never passed as a markup string, so a log line containing
"[red]" or ANSI escape codes cannot restyle or hijack the terminal.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .defense import BlockRule
from .detectors import AnalysisResult
from .utils import SEVERITIES, SEVERITY_STYLE, clean, rel

VERDICT_STYLE = {
    "MALICIOUS": "bold red", "SUSPICIOUS": "bold yellow", "REVIEW": "cyan", "CLEAN": "bold green",
    "UNKNOWN": "dim", "ERROR": "bold yellow", "SKIPPED": "dim",
}
ACTION_STYLE = {"sent": "bold green", "created": "bold green", "dry-run": "bold cyan",
                "skipped": "dim", "not needed": "green", "failed": "bold red"}


def make_console(record: bool = False, width: Optional[int] = None) -> Console:
    return Console(record=record, width=width, highlight=False)


def _severity_badge(severity: str) -> Text:
    return Text(f" {severity.upper():<8} ", style=SEVERITY_STYLE[severity])


def _stat(label: str, value, style: str = "bold") -> Text:
    return Text.assemble((str(value), style), "\n", (label, "dim"))


def _banner(subtitle: str, mock: bool = False) -> Text:
    text = Text()
    text.append("BLUE TEAM AUTO-TRIAGE", style="bold cyan")
    text.append(f"  ·  {subtitle}", style="cyan")
    if mock:
        text.append("   MOCK DATA", style="bold magenta")
    return text


# ---------------------------------------------------------------------------
# Option 1: offline hunt
# ---------------------------------------------------------------------------
def render_hunt(console: Console, result: AnalysisResult, rules: Sequence[BlockRule],
                skipped: Sequence[Tuple[str, str]], outputs: Dict[str, Path]) -> None:
    counts = result.severity_counts()
    verdicts = result.ip_verdicts()
    malicious = sum(v["verdict"] == "MALICIOUS" for v in verdicts)

    header = _banner("Option 1: offline log hunt")
    header.append("\nScanned: ", style="dim")
    header.append(", ".join(clean(rel(f), 60) for f in result.files))
    console.print(Panel(header, box=box.HEAVY, border_style="cyan"))

    stats = Table.grid(expand=True, padding=(0, 1))
    for _ in range(5):
        stats.add_column(justify="center")
    stats.add_row(
        _stat("lines scanned", result.lines_scanned),
        _stat("unique IPs", len(verdicts)),
        _stat("failed SSH logins", sum(result.failed_by_ip.values()), "bold yellow"),
        _stat("findings", len(result.findings), "bold yellow" if result.findings else "bold green"),
        _stat("malicious IPs", malicious, "bold red" if malicious else "bold green"),
    )
    chips = Text(justify="center")
    for severity in reversed(SEVERITIES[1:]):
        chips.append(f" {severity.upper()} {counts.get(severity, 0)} ", style=SEVERITY_STYLE[severity])
        chips.append("  ")
    console.print(Panel(Group(stats, Text(""), chips), title="Summary", border_style="blue"))

    if result.findings:
        table = Table(title="Findings", title_style="bold", box=box.SIMPLE_HEAVY, expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True, style="bold")
        table.add_column("IP", no_wrap=True)
        table.add_column("What happened", ratio=1)
        table.add_column("Where", no_wrap=True, style="dim")
        for f in result.findings:
            what = Text(f.title, style="bold")
            if f.count > 1:
                what.append(f"  ×{f.count}", style="bold magenta")
            what.append(f"\n{clean(f.detail, 120)}", style="dim")
            ip_style = "red" if f.severity in ("high", "critical") else ""
            table.add_row(_severity_badge(f.severity), Text(f.rule), Text(f.ip or "-", style=ip_style),
                          what, Text(f.location))
        console.print(table)
    else:
        console.print(Panel(Text("No threats found in these logs.", style="bold green"), border_style="green"))

    ip_table = Table(title="IP verdicts", title_style="bold", box=box.SIMPLE_HEAVY, expand=True)
    for name, justify in (("IP", "left"), ("Lines", "right"), ("Failed", "right"),
                          ("Logins", "right"), ("Verdict", "left"), ("Why", "left")):
        ip_table.add_column(name, justify=justify, no_wrap=name != "Why", ratio=1 if name == "Why" else None)
    for row in verdicts[:25]:
        style = VERDICT_STYLE[row["verdict"]]
        ip_table.add_row(Text(row["ip"], style=style), str(row["lines"]), str(row["failed_logins"]),
                         str(row["accepted_logins"]), Text(row["verdict"], style=style),
                         Text(", ".join(row["reasons"]) or "-", style="dim"))
    console.print(ip_table)
    if len(verdicts) > 25:
        console.print(Text(f"  … {len(verdicts) - 25} more IPs in the report files", style="dim"))

    if result.failed_usernames:
        users = Text("Most targeted usernames: ", style="bold")
        users.append(", ".join(f"{clean(u, 24)} ({n})" for u, n in result.failed_usernames.most_common(8)))
        console.print(users)
        console.print()

    if rules:
        body = Text()
        width = max(len(rule.command()) for rule in rules)
        for rule in rules:
            body.append(rule.command().ljust(width), style="bold red")
            body.append(f"   # {', '.join(rule.reasons)}\n", style="dim")
        if skipped:
            body.append("Not blocked: " + ", ".join(f"{ip} ({why})" for ip, why in skipped) + "\n", style="yellow")
        if "script" in outputs:
            body.append(f"\nSaved to {rel(outputs['script'])}. Review it, then run: sudo bash {rel(outputs['script'])}",
                        style="dim")
        console.print(Panel(body, title="Active defense (generated, NOT executed)", border_style="red"))

    files = Text("Reports: ", style="bold")
    files.append("  ·  ".join(rel(p) for p in outputs.values()))
    console.print(files)


def write_text_report(result: AnalysisResult, rules: Sequence[BlockRule],
                      skipped: Sequence[Tuple[str, str]], path) -> Path:
    path = Path(path)
    counts = result.severity_counts()
    verdicts = result.ip_verdicts()
    bar, rule_line = "=" * 78, "-" * 78
    lines: List[str] = [
        bar,
        " BLUE TEAM AUTO-TRIAGE: OFFLINE HUNT REPORT",
        bar,
        f"Generated     : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}",
        f"Files         : {', '.join(clean(rel(f), 80) for f in result.files)}",
        f"Lines scanned : {result.lines_scanned}",
        f"Unique IPs    : {len(verdicts)}",
        f"Blocklist     : {result.blocklist_size} entries",
        "",
        "SUMMARY",
        rule_line,
        f"  Attacks / findings detected : {len(result.findings)}",
        "  By severity                 : " + ", ".join(f"{s} {counts.get(s, 0)}" for s in reversed(SEVERITIES[1:])),
        f"  Malicious IPs               : {sum(v['verdict'] == 'MALICIOUS' for v in verdicts)}",
        f"  Failed SSH logins           : {sum(result.failed_by_ip.values())}",
        f"  Successful SSH logins       : {sum(result.accepted_by_ip.values())}",
        "",
        "FINDINGS",
        rule_line,
    ]
    if not result.findings:
        lines.append("  None.")
    for f in result.findings:
        times = f" (x{f.count})" if f.count > 1 else ""
        lines.append(f"[{f.severity.upper():<8}] {f.rule:<21} {f.ip or '-':<16} {f.location}")
        lines.append(f"           {f.title}: {clean(f.detail, 200)}{times}")
    lines += ["", "IP VERDICTS", rule_line,
              f"  {'IP':<18}{'Lines':>6}{'Failed':>8}{'Logins':>8}  {'Verdict':<11} Why"]
    for row in verdicts:
        lines.append(f"  {row['ip']:<18}{row['lines']:>6}{row['failed_logins']:>8}{row['accepted_logins']:>8}"
                     f"  {row['verdict']:<11} {', '.join(row['reasons']) or '-'}")
    if result.failed_usernames:
        lines += ["", "MOST TARGETED USERNAMES", rule_line]
        lines += [f"  {clean(user, 30):<32}{count:>5}" for user, count in result.failed_usernames.most_common(15)]
    lines += ["", "ACTIVE DEFENSE (review before running; nothing was executed)", rule_line]
    lines += [f"  {r.command():<48} # {', '.join(r.reasons)}" for r in rules] or ["  Nothing to block."]
    lines += [f"  not blocked: {ip} ({why})" for ip, why in skipped]
    lines += [bar, ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_json_report(result: AnalysisResult, rules: Sequence[BlockRule], path) -> Path:
    path = Path(path)
    data = {
        "tool": "blue-team-auto-triage",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": result.files,
        "stats": {
            "lines_scanned": result.lines_scanned,
            "events_by_kind": dict(result.events_by_kind),
            "failed_ssh_logins": sum(result.failed_by_ip.values()),
            "findings_by_severity": dict(result.severity_counts()),
        },
        "findings": [asdict(f) for f in result.findings],
        "ip_verdicts": result.ip_verdicts(),
        "block_rules": [{"ip": r.ip, "direction": r.direction, "reasons": r.reasons, "command": r.command()}
                        for r in rules],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Option 2: alert pipeline
# ---------------------------------------------------------------------------
def _short(indicator: str) -> str:
    return indicator if len(indicator) <= 22 else f"{indicator[:14]}…{indicator[-6:]}"


def render_alert(console: Console, report) -> None:
    head = _banner("Option 2: API-driven alert pipeline", report.mock)
    for label, value in (("\nAlert ", report.alert_id), ("   Rule ", f"{report.rule_id} (level {report.rule_level})"),
                         ("   Time ", report.timestamp)):
        head.append(label, style="dim")
        head.append(value)
    head.append("\n")
    head.append(report.rule_description, style="bold")
    head.append("\nHost  ", style="dim")
    head.append(f"{report.agent_name} ({report.agent_ip})")
    if report.username:
        head.append("   User ", style="dim")
        head.append(report.username)
    if report.file_path:
        head.append("\nFile  ", style="dim")
        head.append(report.file_path)
    console.print(Panel(head, box=box.HEAVY, border_style="cyan"))

    table = Table(title="Threat enrichment", title_style="bold", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Provider", no_wrap=True, style="bold")
    table.add_column("Indicator", no_wrap=True)
    table.add_column("Score", no_wrap=True, justify="right")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Details", ratio=1)
    for r in report.results:
        style = VERDICT_STYLE[r.verdict]
        table.add_row(r.provider, Text(f"{r.kind}: {_short(r.indicator)}"), Text(r.score_text, style=style),
                      Text(r.verdict, style=style), Text(clean(r.error or r.summary, 120), style="dim"))
    if not report.results:
        table.add_row("-", "-", "-", Text("no indicators", style="dim"), "")
    console.print(table)
    if report.skipped:
        console.print(Text("Not enriched: " + "; ".join(f"{ip} ({why})" for ip, why in report.skipped), style="dim"))
        console.print()

    verdict = Text("SEVERITY ", style="bold")
    verdict.append(f" {report.severity.upper()} ", style=SEVERITY_STYLE[report.severity])
    verdict.append("   escalate: notify the team + open a case" if report.flagged else "   no escalation needed",
                   style="bold red" if report.flagged else "bold green")
    recs = Text("\n".join(f"• {r}" for r in report.recommendations))
    console.print(Panel(Group(verdict, Text(""), recs), title="Verdict & recommendations",
                        border_style="red" if report.flagged else "green"))

    actions = Table(title="Automated actions", title_style="bold", box=box.SIMPLE_HEAVY, expand=True)
    actions.add_column("Action", no_wrap=True, style="bold")
    actions.add_column("Status", no_wrap=True)
    actions.add_column("Detail", ratio=1)
    for name, status, detail in report.actions:
        actions.add_row(name, Text(status.upper(), style=ACTION_STYLE.get(status, "")), Text(detail, style="dim"))
    console.print(actions)
