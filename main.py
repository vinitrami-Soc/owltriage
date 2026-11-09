#!/usr/bin/env python3
"""Blue Team Auto-Triage: command-line entry point.

    python main.py hunt                       # Option 1: offline log analysis
    python main.py alert --mock --dry-run     # Option 2: API pipeline demo, no keys needed
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from triage import __version__
from triage.config import PROJECT_ROOT, load_settings
from triage.defense import parse_allowlist, plan_blocks, write_script
from triage.detectors import analyze
from triage.intel import BadIPList
from triage.pipeline import TriagePipeline, load_alerts
from triage.reporting import (make_console, render_alert, render_hunt, write_json_report,
                              write_text_report)
from triage.utils import SEVERITIES, SEVERITY_RANK

DATA = PROJECT_ROOT / "data"
SVG_WIDTH = 120


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Blue Team Auto-Triage: offline log hunting + API-driven alert enrichment.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    hunt = sub.add_parser("hunt", help="Option 1: offline log analysis (no internet or API keys)")
    hunt.add_argument("logs", nargs="*", type=Path,
                      help="log files to scan (default: data/auth.log data/access.log)")
    hunt.add_argument("--bad-ips", type=Path, default=DATA / "bad_ips.txt", help="local IP/CIDR blocklist")
    hunt.add_argument("--threshold", type=int, default=5,
                      help="failed SSH logins from one IP before it counts as brute force (default 5)")
    hunt.add_argument("--allow", action="append", default=[], metavar="IP_OR_CIDR",
                      help="never generate block rules for this IP/range, e.g. your admin VPN (repeatable)")
    hunt.add_argument("--fail-on", choices=SEVERITIES[1:], metavar="SEVERITY",
                      help="exit with code 1 if any finding is at least this severity (for cron/CI)")
    hunt.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "output")
    hunt.add_argument("--svg", type=Path, help="also save the terminal output as an SVG screenshot")

    alert = sub.add_parser("alert", help="Option 2: enrich a Wazuh alert, notify chat, open a TheHive case")
    alert.add_argument("alert_file", type=Path, nargs="?", default=DATA / "dummy_alert.json",
                       help="alert JSON: one object, a list, or Wazuh alerts.json lines (default: data/dummy_alert.json)")
    alert.add_argument("--mock", action="store_true",
                       help="answer VirusTotal/AbuseIPDB lookups from data/mock_intel.json (no keys, no internet)")
    alert.add_argument("--dry-run", action="store_true",
                       help="build the Discord/Slack/TheHive payloads and save them to output/dry_run/ instead of sending")
    alert.add_argument("--no-notify", action="store_true", help="never send chat notifications")
    alert.add_argument("--no-case", action="store_true", help="never create TheHive cases")
    alert.add_argument("--env-file", type=Path, help="path to a .env file (default: project .env)")
    alert.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "output")
    alert.add_argument("--svg", type=Path, help="also save the terminal output as an SVG screenshot")
    return parser


def cmd_hunt(args, console) -> int:
    logs = args.logs or [DATA / "auth.log", DATA / "access.log"]
    missing = [str(p) for p in logs if not p.is_file()]
    if missing:
        console.print(f"[bold red]Log file not found:[/] {', '.join(missing)}", markup=True)
        return 2
    try:
        allowlist = parse_allowlist(args.allow)
    except ValueError as exc:
        console.print(f"[bold red]Bad --allow value:[/] {exc}", markup=True)
        return 2

    if args.bad_ips and args.bad_ips.is_file():
        bad_ips = BadIPList.load(args.bad_ips)
    else:
        console.print(f"[yellow]Blocklist {args.bad_ips} not found; continuing without it.[/]", markup=True)
        bad_ips = BadIPList()

    result = analyze(logs, bad_ips, args.threshold)
    rules, skipped = plan_blocks(result.findings, allowlist)

    outputs = {
        "text": write_text_report(result, rules, skipped, args.out_dir / "triage_report.txt"),
        "json": write_json_report(result, rules, args.out_dir / "triage_report.json"),
    }
    if rules:
        outputs["script"] = write_script(rules, args.out_dir / "block_ips.sh")

    render_hunt(console, result, rules, skipped, outputs)
    for line_no, entry in bad_ips.invalid:
        console.print(f"[yellow]Ignored invalid blocklist entry on line {line_no}[/]", markup=True)

    if args.fail_on and any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in result.findings):
        return 1
    return 0


def cmd_alert(args, console) -> int:
    if not args.alert_file.is_file():
        console.print(f"[bold red]Alert file not found:[/] {args.alert_file}", markup=True)
        return 2
    try:
        alerts = load_alerts(args.alert_file)
    except (ValueError, json.JSONDecodeError) as exc:
        console.print(f"[bold red]Could not read alerts:[/] {exc}", markup=True)
        return 2

    settings = load_settings(args.env_file)
    if not args.mock and not settings.vt_api_key:
        console.print("[yellow]VT_API_KEY is not set. Add it to .env, or run with --mock for a demo.[/]",
                      markup=True)

    pipeline = TriagePipeline(settings, mock=args.mock, dry_run=args.dry_run, notify=not args.no_notify,
                              create_case=not args.no_case, out_dir=args.out_dir)
    for alert in alerts:
        render_alert(console, pipeline.run(alert))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = make_console(record=bool(args.svg), width=SVG_WIDTH if args.svg else None)
    handler = cmd_hunt if args.command == "hunt" else cmd_alert
    code = handler(args, console)
    if args.svg:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        title = "python main.py " + " ".join(sys.argv[1:] if argv is None else argv)
        console.save_svg(str(args.svg), title=title.replace(f" --svg {args.svg}", ""))
    return code


if __name__ == "__main__":
    sys.exit(main())
