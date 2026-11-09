"""Security boundaries and robustness: hostile log lines, malformed alerts, fuzzing, ReDoS."""
import io
import json
import re
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from rich.console import Console

from bluetriage.config import Settings
from bluetriage.defense import plan_blocks
from bluetriage.detectors import Analyzer, decode_base64_blobs
from bluetriage.intel import BadIPList
from bluetriage.log_parser import extract_ips, normalize_ip, parse_line, url_decode
from bluetriage.notify import build_discord_payload, build_slack_payload
from bluetriage.pipeline import TriagePipeline, TriageReport, assess, extract_observables
from bluetriage.enrichment import IntelResult
from bluetriage.reporting import render_alert, render_hunt, write_text_report
from bluetriage.utils import clean


class NoNetwork:
    headers = {}

    def get(self, *a, **k):
        raise AssertionError("network")

    post = get


def analyze_lines(lines, bad_ips=None):
    analyzer = Analyzer(bad_ips)
    for no, line in enumerate(lines, 1):
        analyzer.feed(parse_line(line, no, "evil.log"))
    return analyzer.finish()


HOSTILE = [
    # ANSI: clear screen + fake green "all clear" + OSC hyperlink
    'Nov  9 03:11:45 web01 sshd[1]: Failed password for invalid user \x1b[2J\x1b[32mALL CLEAR\x1b]8;;http://evil\x07 '
    'from 203.0.113.5 port 1 ssh2',
    # Rich markup that would raise MarkupError or recolor if parsed as markup
    'Nov  9 03:11:46 web01 sshd[1]: Failed password for invalid user [/][bold green]SAFE[/] from 203.0.113.5 port 2 ssh2',
    # newline tricks are impossible inside one physical line, but \r and bidi controls are not
    'Nov  9 03:11:47 web01 sshd[1]: Failed password for invalid user a\rb\u202eevil from 203.0.113.5 port 3 ssh2',
] * 2


def test_hostile_log_content_cannot_control_the_terminal():
    result = analyze_lines(HOSTILE)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=160, color_system="truecolor")
    render_hunt(console, result, *plan_blocks(result.findings), outputs={})
    out = buf.getvalue()
    assert "\x1b[2J" not in out and "\x1b]8;;http://evil" not in out
    assert "\r" not in out and "\u202e" not in out
    assert "[bold green]" in out  # printed literally, not interpreted


def test_hostile_usernames_cannot_forge_report_lines(tmp_path):
    result = analyze_lines(HOSTILE)
    text = write_text_report(result, [], [], tmp_path / "r.txt").read_text()
    assert "\x1b" not in text and "\r" not in text and "\u202e" not in text
    assert all(not line.startswith("[CRITICAL]") for line in text.splitlines())


def test_hostile_alert_cannot_ping_everyone_or_break_markdown():
    report = TriageReport(alert_id="1", timestamp="t", rule_id="1", rule_level=12,
                          rule_description="@everyone <!channel> `pwn` [click](http://evil)",
                          agent_name="web01", agent_ip="10.0.0.1", severity="high", flagged=True,
                          recommendations=["x"], file_path="/tmp/`a`")
    discord = build_discord_payload(report)
    assert discord["allowed_mentions"] == {"parse": []}
    assert "`a`" not in json.dumps(discord)
    slack = json.dumps(build_slack_payload(report))
    assert "<!channel>" not in slack and "&lt;!channel&gt;" in slack


def test_chat_payloads_respect_platform_limits():
    """Discord: title 256, field name 256, value 1024, 25 fields, 6000 chars total. Slack: header 150, text 3000."""
    long = "A" * 10_000
    results = [IntelResult("VirusTotal", f"203.0.113.{i}", "ip", score=50, out_of=90, flagged=True, found=True,
                           summary=long, link="https://www.virustotal.com/gui/ip-address/x") for i in range(40)]
    report = TriageReport(alert_id=long, timestamp="t", rule_id=long, rule_level=15, rule_description=long,
                          agent_name=long, agent_ip="10.0.0.1", file_path=long, results=results,
                          severity="critical", flagged=True, recommendations=[long] * 5)
    embed = build_discord_payload(report)["embeds"][0]
    assert len(embed["title"]) <= 256 and len(embed["description"]) <= 4096
    assert len(embed["fields"]) <= 25
    assert all(len(f["name"]) <= 256 and 0 < len(f["value"]) <= 1024 for f in embed["fields"])
    total = len(embed["title"]) + len(embed["description"]) + len(embed["footer"]["text"]) + sum(
        len(f["name"]) + len(f["value"]) for f in embed["fields"])
    assert total <= 6000, f"Discord rejects embeds over 6000 characters (got {total})"

    slack = build_slack_payload(report)
    assert len(slack["blocks"][0]["text"]["text"]) <= 150
    assert all(len(f["text"]) <= 2000 for f in slack["blocks"][1]["fields"])
    assert all(len(b["text"]["text"]) <= 3000 for b in slack["blocks"][2:4])


MALFORMED_ALERTS = [
    {},
    {"rule": "not-a-dict", "agent": None, "data": []},
    {"rule": {"level": "abc", "description": {"nested": True}}},
    {"rule": {"mitre": {"id": "T1105"}}},  # string instead of list
    {"data": {"srcip": 12345, "dstip": ["203.0.113.5"]}},
    {"data": {"srcip": "999.1.1.1"}, "syscheck": {"sha256_after": None}},
    {"syscheck": {"sha256_after": 42}},
    {"full_log": 123, "id": {"x": 1}},
    {"full_log": "x" * 200_000},
]


@pytest.mark.parametrize("alert", MALFORMED_ALERTS)
def test_malformed_alerts_never_crash(alert, tmp_path):
    report = TriagePipeline(Settings(), mock=True, dry_run=True, out_dir=tmp_path, session=NoNetwork()).run(alert)
    render_alert(Console(file=io.StringIO(), width=120), report)
    assert report.severity in ("low", "medium", "high", "critical")


def test_mitre_id_as_plain_string_is_kept_whole():
    report = TriageReport.from_alert({"rule": {"mitre": {"id": "T1105"}}})
    assert report.mitre == ["T1105"]


@pytest.mark.parametrize("vt, abuse, expected", [
    (0, 0, ("low", False)),
    (5, 0, ("medium", False)),    # roadmap: escalate only when VT score > 5; 5 is a weak signal
    (6, 0, ("high", True)),
    (0, 49, ("medium", False)),
    (0, 50, ("high", True)),
    (19, 0, ("high", True)),
    (20, 0, ("critical", True)),  # 4 x threshold
    (6, 50, ("critical", True)),  # both providers agree
])
def test_severity_thresholds(vt, abuse, expected):
    results = [IntelResult("VirusTotal", "x", "ip", score=vt, out_of=90, found=True, flagged=vt > 5),
               IntelResult("AbuseIPDB", "x", "ip", score=abuse, out_of=100, found=True, flagged=abuse >= 50)]
    assert assess(results, 5) == expected


# ---------------------------------------------------------------- fuzzing
FUZZ = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
log_text = st.one_of(
    st.text(max_size=400),
    st.binary(max_size=400).map(lambda b: b.decode("utf-8", "replace")),
    st.builds(lambda u, ip: f"Nov  9 03:00:00 h sshd[1]: Failed password for {u} from {ip} port 22 ssh2",
              st.text(max_size=60), st.text(max_size=40)),
    st.builds(lambda ip, p, ua: f'{ip} - - [09/Nov/2026:03:00:00 +0000] "GET {p} HTTP/1.1" 200 1 "-" "{ua}"',
              st.ip_addresses().map(str), st.text(max_size=80).map(lambda s: "/" + s.replace(" ", "%20")),
              st.text(max_size=40).map(lambda s: s.replace('"', ""))),
)


@FUZZ
@given(st.lists(log_text, max_size=8))
def test_fuzz_analyzer_never_crashes(lines):
    result = analyze_lines(lines)
    for finding in result.findings:
        if finding.ip:
            assert normalize_ip(finding.ip) == finding.ip
    rules, _ = plan_blocks(result.findings)
    for rule in rules:
        assert re.fullmatch(r"ip6?tables -A (INPUT -s|OUTPUT -d) [0-9a-f.:]+ -j DROP", rule.command())


@FUZZ
@given(st.text(max_size=300))
def test_fuzz_helpers_never_crash(text):
    for ip in extract_ips(text):
        assert normalize_ip(ip) == ip
    url_decode(text)
    decode_base64_blobs(text)
    cleaned = clean(text, 50)
    assert len(cleaned) <= 50 and not re.search(r"[\x00-\x1f\x7f-\x9f]", cleaned)


@FUZZ
@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=30),
                    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=4),
                    max_leaves=20))
def test_fuzz_observable_extraction(alert):
    if isinstance(alert, dict):
        found, _ = extract_observables(alert)
        for obs in found:
            assert obs.kind in ("ip", "hash")


def test_fuzz_blocklist_lines():
    bl = BadIPList()
    for line in ["", "#", "   # only comment", "1.2.3.4/33", "::/0 # everything", "10.0.0.0/8", "garbage # x"]:
        bl.add_line(line)
    assert bl.lookup("10.1.2.3") == "listed in bad_ips.txt [10.0.0.0/8]"
    assert bl.lookup("2001:db8::1") == "everything [::/0]"
    assert [entry for _, entry in bl.invalid] == ["1.2.3.4/33", "garbage"]


# ---------------------------------------------------------------- ReDoS
PATHOLOGICAL = {
    "ssh: many 'from' tokens": "Nov  9 03:00:00 h sshd[1]: Failed password for " + "x from 1.1.1.1 " * 4000,
    "ssh: repeated prefixes": "Failed password for " * 3000 + "root from 203.0.113.5",
    "base64: long run": "A" * 200_000 + "===",
    "base64: many short runs": ("QUFBQUFBQUFBQUFBQUFBQQ " * 10_000),
    "sqli: tautology backtracking": "/?q=" + "or " * 20_000 + "a" * 20_000,
    "ipv4 lookalikes": "1." * 50_000,
}


@pytest.mark.parametrize("name", PATHOLOGICAL)
def test_no_catastrophic_regex_backtracking(name):
    line = PATHOLOGICAL[name]
    web = f'203.0.113.9 - - [09/Nov/2026:03:00:00 +0000] "GET {line[:60_000]} HTTP/1.1" 200 1 "-" "x"'
    started = time.perf_counter()
    analyze_lines([line, web])
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"{name}: {elapsed:.2f}s"


# ---------------------------------------------------------------- source hygiene
# Built with chr() on purpose: typing the escapes has twice produced the literal
# characters in this repo, which is exactly what this test exists to catch.
INVISIBLE = re.compile("[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in
                                     ((0x200B, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069))) + "]")


def test_no_trojan_source_characters_in_repo():
    root = Path(__file__).resolve().parent.parent
    files = [p for p in root.rglob("*") if p.suffix in {".py", ".md", ".txt", ".json", ".log", ".sh", ".ini"}
             and ".git" not in p.parts and "output" not in p.parts]
    offenders = [str(p.relative_to(root)) for p in files if INVISIBLE.search(p.read_text(encoding="utf-8", errors="ignore"))]
    assert offenders == [], f"hidden bidi/zero-width characters in: {offenders}"
