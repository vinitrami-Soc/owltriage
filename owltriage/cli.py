"""owltriage command line.

    owltriage hunt --demo                       # try it: bundled Linux, web and Windows attack samples
    owltriage hunt /var/log/auth.log access.log Security.evtx
    owltriage update-feeds                      # download free threat feeds (optional, cron daily)
    owltriage rules list | rules test           # detection-as-code
    owltriage alert --demo                      # Wazuh alert -> VirusTotal/AbuseIPDB -> Discord/Slack/TheHive
"""
from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .config import load_settings
from .defense import parse_allowlist, plan_blocks, write_script
from .banner import HuntProgress, OwlShow, animation_mode, print_logo
from .detectors import ScanProgress, analyze
from .exporters import write_attack_layer, write_findings_ndjson, write_iocs_csv, write_stix_bundle
from .feeds import default_feeds_dir, load_feed_specs, load_feeds_into, update_feeds
from .intel import BadIPList
from .pipeline import TriagePipeline, load_alerts, report_summary
from .reporting import make_console, render_alert, render_hunt, write_json_report, write_text_report
from .rules import RuleError, load_rules, run_rule_tests
from .summary import summarize
from .utils import SEVERITIES, SEVERITY_RANK, clean

SAMPLES = Path(__file__).resolve().parent / "resources" / "samples"
DEMO_LOGS = [SAMPLES / "auth.log", SAMPLES / "access.log", SAMPLES / "windows_security.xml"]
SVG_WIDTH = 150


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owltriage",
        description="ATT&CK-mapped log hunting (Linux, web, Windows) and alert enrichment for blue teams.",
        epilog="Docs: README.md · rule format: docs/RULES.md")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def common(p, svg: bool = True):
        p.add_argument("--out-dir", type=Path, default=Path("owltriage-output"),
                       help="where reports go (default: ./owltriage-output)")
        p.add_argument("--quiet", action="store_true", help="no terminal report (files and exit code only)")
        if svg:
            p.add_argument("--svg", type=Path, help="also save the terminal output as an SVG screenshot")

    hunt = sub.add_parser("hunt", help="analyze log files offline (auth.log, access logs, .evtx / XML / JSON)")
    hunt.add_argument("logs", nargs="*", type=Path, help="log files; format is auto-detected")
    hunt.add_argument("--demo", action="store_true", help="scan the bundled attack samples")
    hunt.add_argument("--bad-ips", type=Path, action="append", default=[], metavar="FILE",
                      help="your own IP/CIDR blocklist, one per line (repeatable)")
    hunt.add_argument("--feeds-dir", type=Path, help=f"threat feed cache (default: {default_feeds_dir()})")
    hunt.add_argument("--no-feeds", action="store_true", help="do not load downloaded threat feeds")
    hunt.add_argument("--rules-dir", type=Path, action="append", default=[], metavar="DIR",
                      help="extra YAML rules; same id = override a built-in rule (repeatable)")
    hunt.add_argument("--threshold", type=int, help="failed logins per IP for brute force (rule default: 5)")
    hunt.add_argument("--window", type=int, metavar="SECONDS",
                      help="brute-force time window (rule default: 600; 0 = whole file)")
    hunt.add_argument("--year", type=int, help="year for syslog timestamps that have none (default: this year)")
    hunt.add_argument("--allow", action="append", default=[], metavar="IP_OR_CIDR",
                      help="never generate block rules for this IP/range, e.g. your VPN (repeatable)")
    hunt.add_argument("--fail-on", choices=SEVERITIES[1:], metavar="SEVERITY",
                      help="exit 1 if any finding is at least this severity (cron/CI)")
    hunt.add_argument("--no-anim", action="store_true",
                      help="no owl animation (also off automatically for pipes, cron, CI and --quiet)")
    common(hunt)

    alert = sub.add_parser("alert", help="enrich Wazuh alerts, notify chat, open TheHive cases")
    alert.add_argument("alert_file", type=Path, nargs="?",
                       help="alert JSON: one object, a list, or Wazuh alerts.json lines")
    alert.add_argument("--demo", action="store_true", help="bundled sample alert with --mock --dry-run")
    alert.add_argument("--mock", action="store_true", help="fake VirusTotal/AbuseIPDB answers (no keys needed)")
    alert.add_argument("--dry-run", action="store_true", help="save Discord/Slack/TheHive payloads instead of sending")
    alert.add_argument("--no-notify", action="store_true", help="never send chat notifications")
    alert.add_argument("--no-case", action="store_true", help="never create TheHive cases")
    alert.add_argument("--env-file", type=Path, help="settings file (default: ./.env)")
    common(alert)

    rules = sub.add_parser("rules", help="list or self-test detection rules")
    rules.add_argument("action", choices=("list", "test"))
    rules.add_argument("ids", nargs="*", help="only these rule ids (test)")
    rules.add_argument("--rules-dir", type=Path, action="append", default=[], metavar="DIR")
    rules.add_argument("--type", choices=("web", "command", "line", "event", "correlation"), help="filter (list)")

    feeds = sub.add_parser("update-feeds", help="download free IP threat feeds into the local cache")
    feeds.add_argument("--feeds-dir", type=Path, help=f"cache directory (default: {default_feeds_dir()})")
    feeds.add_argument("--feeds-config", type=Path, help="YAML list of feeds (default: built-in list)")
    feeds.add_argument("--only", action="append", default=[], metavar="ID", help="update only this feed (repeatable)")
    feeds.add_argument("--list", action="store_true", help="show configured feeds and cache status, download nothing")
    return parser


def _load_rules(args, err: Console):
    try:
        return load_rules(args.rules_dir)
    except RuleError as exc:
        err.print(Text(f"Rule error: {exc}", style="bold red"))
        return None


def cmd_hunt(args, console: Console, err: Console) -> int:
    logs: List[Path] = list(args.logs)
    if args.demo:
        logs += DEMO_LOGS
        args.bad_ips.append(SAMPLES / "bad_ips.txt")
        args.no_feeds = True  # the demo must give the same result everywhere
    if not logs:
        err.print(Text("No log files given. Try: owltriage hunt --demo   or   owltriage hunt /var/log/auth.log",
                       style="bold red"))
        return 2
    missing = [str(p) for p in logs if not p.is_file()]
    if missing:
        err.print(Text(f"Log file not found: {', '.join(missing)}", style="bold red"))
        return 2
    try:
        allowlist = parse_allowlist(args.allow)
    except ValueError as exc:
        err.print(Text(f"Bad --allow value: {exc}", style="bold red"))
        return 2
    ruleset = _load_rules(args, err)
    if ruleset is None:
        return 2

    # The owl: animated on an interactive terminal only (never for pipes, cron, CI, --quiet, --svg).
    show = OwlShow(console, animation_mode(console, wanted=not (args.no_anim or args.quiet or args.svg)))
    show.start()
    try:
        return _hunt(args, console, err, logs, allowlist, ruleset, show)
    finally:
        show.stop()


def _hunt(args, console: Console, err: Console, logs: List[Path], allowlist, ruleset, show: OwlShow) -> int:
    bad_ips = BadIPList()
    for path in args.bad_ips:
        if path.is_file():
            bad_ips.load_file(path)
        else:
            err.print(Text(f"Blocklist {path} not found; continuing without it.", style="yellow"))
    feed_note = ""
    if not args.no_feeds:
        infos = load_feeds_into(bad_ips, args.feeds_dir)
        if not infos:
            feed_note = "Threat feeds: none downloaded yet (optional): run `owltriage update-feeds`"
        else:
            oldest = max((i.age_days or 999) for i in infos)
            stale = " - stale, run `owltriage update-feeds`" if any(i.stale for i in infos) else ""
            feed_note = (f"Threat feeds: {', '.join(f'{i.id} ({i.entries:,})' for i in infos)}; "
                         f"oldest {oldest:.1f} days{stale}")

    def progress(p: ScanProgress) -> None:
        show.update(HuntProgress(p.file, p.file_no, p.files, p.events, p.findings, p.fraction))

    result = analyze(logs, bad_ips, args.threshold, ruleset, args.window, args.year,
                     on_progress=progress if show.mode != "off" else None)
    rules, skipped = plan_blocks(result.findings, allowlist)
    summary = summarize(result, rules)

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    outputs = {
        "text": write_text_report(result, rules, skipped, out / "triage_report.txt", ruleset, summary),
        "json": write_json_report(result, rules, out / "triage_report.json", summary),
        "ndjson": write_findings_ndjson(result, ruleset, out / "findings.ndjson"),
        "csv": write_iocs_csv(result, out / "iocs.csv"),
        "stix": write_stix_bundle(result, out / "iocs.stix.json"),
        "layer": write_attack_layer(result, ruleset, out / "attack_layer.json"),
    }
    if rules:
        outputs["script"] = write_script(rules, out / "block_ips.sh")

    malicious = sum(v["verdict"] == "MALICIOUS" for v in result.ip_verdicts())
    show.finish(Text(f"✔ hunt complete: {len(result.findings)} findings, {malicious} malicious IPs, "
                     f"{len(result.technique_counts())} ATT&CK techniques", style="bold #4ade80"))
    if not args.quiet and (console.is_terminal or args.svg):
        print_logo(console, len(ruleset.enabled()))
    render_hunt(console, result, rules, skipped, outputs, ruleset, feed_note, summary)
    for line_no, entry in bad_ips.invalid:
        err.print(Text(f"Ignored invalid blocklist entry on line {line_no}: {clean(entry, 60)}", style="yellow"))
    if args.fail_on and any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in result.findings):
        return 1
    return 0


def cmd_alert(args, console: Console, err: Console) -> int:
    if args.demo:
        args.alert_file = args.alert_file or SAMPLES / "dummy_alert.json"
        args.mock = args.dry_run = True
    if args.alert_file is None:
        err.print(Text("No alert file given. Try: owltriage alert --demo", style="bold red"))
        return 2
    if not args.alert_file.is_file():
        err.print(Text(f"Alert file not found: {args.alert_file}", style="bold red"))
        return 2
    try:
        alerts = load_alerts(args.alert_file)
    except (ValueError, json.JSONDecodeError) as exc:
        err.print(Text(f"Could not read alerts: {clean(exc, 150)}", style="bold red"))
        return 2

    settings = load_settings(args.env_file)
    if not args.mock and not settings.vt_api_key:
        err.print(Text("VT_API_KEY is not set. Add it to .env, or try --demo / --mock.", style="yellow"))

    pipeline = TriagePipeline(settings, mock=args.mock, dry_run=args.dry_run, notify=not args.no_notify,
                              create_case=not args.no_case, out_dir=args.out_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with (args.out_dir / "alert_results.ndjson").open("a", encoding="utf-8") as audit:
        for alert in alerts:
            report = pipeline.run(alert)
            audit.write(json.dumps(report_summary(report)) + "\n")
            render_alert(console, report)
    return 0


def cmd_rules(args, console: Console, err: Console) -> int:
    ruleset = _load_rules(args, err)
    if ruleset is None:
        return 2
    if args.action == "list":
        table = Table(box=box.SIMPLE_HEAVY, title=f"{len(ruleset.rules)} rules", title_style="bold")
        for column in ("id", "type", "severity", "ATT&CK", "title", "enabled"):
            table.add_column(column, no_wrap=column in ("id", "type", "severity"))
        for rule in sorted(ruleset.rules.values(), key=lambda r: (r.type, r.id)):
            if args.type and rule.type != args.type:
                continue
            table.add_row(rule.id, rule.type, rule.severity, ", ".join(rule.mitre) or "-", Text(rule.title),
                          "yes" if rule.enabled else Text("no", style="dim"))
        console.print(table)
        return 0

    results = run_rule_tests(ruleset, args.ids)
    failed = [r for r in results if not r.ok]
    for result in results:
        mark = Text("PASS ", style="bold green") if result.ok else Text("FAIL ", style="bold red")
        mark.append(f"{result.rule.id}  ({result.examples} examples)")
        console.print(mark)
        for failure in result.failures:
            console.print(Text(f"      {failure}", style="red"))
    examples = sum(r.examples for r in results)
    summary = f"{len(results) - len(failed)}/{len(results)} rules passed, {examples} examples"
    console.print(Text(summary, style="bold red" if failed else "bold green"))
    return 1 if failed else 0


def cmd_update_feeds(args, console: Console, err: Console) -> int:
    try:
        specs = load_feed_specs(args.feeds_config)
    except (OSError, ValueError) as exc:
        err.print(Text(f"Feeds config error: {clean(exc, 200)}", style="bold red"))
        return 2
    feeds_dir = args.feeds_dir or default_feeds_dir()
    if args.list:
        cached = {i.id: i for i in load_feeds_into(BadIPList(), feeds_dir)}
        table = Table(box=box.SIMPLE_HEAVY, title=f"Feeds (cache: {feeds_dir})", title_style="bold")
        for column in ("id", "enabled", "cached entries", "age (days)", "description"):
            table.add_column(column)
        for spec in specs:
            info = cached.get(spec.id)
            table.add_row(spec.id, "yes" if spec.enabled else "no", f"{info.entries:,}" if info else "-",
                          f"{info.age_days:.1f}" if info and info.age_days is not None else "-",
                          Text(spec.description))
        console.print(table)
        return 0
    results = update_feeds(specs, feeds_dir, only=args.only)
    style = {"updated": "bold green", "failed": "bold red", "skipped": "dim"}
    for r in results:
        line = Text(f"{r.status.upper():8} ", style=style[r.status])
        line.append(f"{r.id:<18} ")
        if r.status == "updated":
            line.append(f"{r.entries:,} entries" + (f", {r.dropped} private/reserved dropped" if r.dropped else ""))
        line.append(f"  {r.detail}", style="dim")
        console.print(line)
    console.print(Text(f"Cache: {feeds_dir}", style="dim"))
    attempted = [r for r in results if r.status != "skipped"]
    return 1 if attempted and all(r.status == "failed" for r in attempted) else 0


def _utf8_stdio() -> None:
    """Windows pipes and redirects default to a legacy code page (cp1252) that can't encode the
    owl, the bar or non-ASCII log content; without this, `owltriage hunt x > report.txt` crashes."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "").replace("_", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            with contextlib.suppress(ValueError, OSError):  # e.g. a stream already used in binary mode
                stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: Optional[List[str]] = None) -> int:
    _utf8_stdio()
    parser = build_parser()
    if not (sys.argv[1:] if argv is None else argv):  # bare `owltriage`: say hello, then show usage
        console = make_console()
        if console.is_terminal:
            print_logo(console)
        parser.print_help()
        return 0
    args = parser.parse_args(argv)
    svg = getattr(args, "svg", None)
    console = make_console(record=bool(svg), width=SVG_WIDTH if svg else None,
                           quiet=getattr(args, "quiet", False) and not svg)
    err = Console(stderr=True, highlight=False)
    handler = {"hunt": cmd_hunt, "alert": cmd_alert, "rules": cmd_rules, "update-feeds": cmd_update_feeds}
    code = handler[args.command](args, console, err)
    if svg:
        svg.parent.mkdir(parents=True, exist_ok=True)
        shown = [a for a in (sys.argv[1:] if argv is None else argv)]
        if "--svg" in shown:
            index = shown.index("--svg")
            del shown[index:index + 2]
        console.save_svg(str(svg), title="owltriage " + " ".join(shown))
    return code


if __name__ == "__main__":
    sys.exit(main())
