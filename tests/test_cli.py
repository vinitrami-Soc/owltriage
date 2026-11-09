"""End-to-end tests: run the CLI as a real subprocess, the way a user (or cron) would."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "bluetriage" / "resources" / "samples"
SECRET_VARS = ("VT_API_KEY", "ABUSEIPDB_API_KEY", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL",
               "THEHIVE_URL", "THEHIVE_API_KEY")


def cli(*args, cwd=None, feeds_dir=None):
    env = {k: v for k, v in os.environ.items() if k not in SECRET_VARS}
    env["COLUMNS"] = "200"
    env["PYTHONPATH"] = str(ROOT)
    env["BLUETRIAGE_FEEDS_DIR"] = str(feeds_dir or ROOT / "tests" / "no-feeds-here")
    return subprocess.run([sys.executable, "-m", "bluetriage", *map(str, args)], capture_output=True, text=True,
                          cwd=cwd or ROOT, env=env, timeout=120)


def test_demo_hunt_writes_every_output(tmp_path):
    run = cli("hunt", "--demo", "--out-dir", tmp_path)
    assert run.returncode == 0, run.stderr
    for marker in ("COMPROMISE_SUSPECTED", "RANSOMWARE_PRECURSOR", "T1110.003", "RDP brute force"):
        assert marker in run.stdout
    for name in ("triage_report.txt", "triage_report.json", "findings.ndjson", "iocs.csv", "iocs.stix.json",
                 "attack_layer.json", "block_ips.sh"):
        assert (tmp_path / name).is_file(), name
    report = json.loads((tmp_path / "triage_report.json").read_text())
    assert report["stats"]["log_types"] == {"text": 34, "web": 14, "windows": 17}
    if shutil.which("bash") and sys.platform != "win32":
        assert subprocess.run(["bash", "-n", str(tmp_path / "block_ips.sh")]).returncode == 0
    ndjson = [json.loads(line) for line in (tmp_path / "findings.ndjson").read_text().splitlines()]
    assert len(ndjson) == len(report["findings"])


def test_fail_on_gives_nonzero_exit_for_cron(tmp_path):
    assert cli("hunt", "--demo", "--out-dir", tmp_path, "--fail-on", "critical", "--quiet").returncode == 1
    clean_log = tmp_path / "clean.log"
    clean_log.write_text("Nov  9 03:00:14 web01 sshd[1]: Accepted publickey for ops from 192.168.1.10 port 5 ssh2\n")
    assert cli("hunt", clean_log, "--out-dir", tmp_path / "o", "--fail-on", "low").returncode == 0


def test_quiet_prints_nothing(tmp_path):
    run = cli("hunt", "--demo", "--out-dir", tmp_path, "--quiet")
    assert run.returncode == 0 and run.stdout == ""
    assert (tmp_path / "triage_report.txt").exists()


def test_clean_log_produces_no_block_script(tmp_path):
    clean_log = tmp_path / "clean.log"
    clean_log.write_text('192.0.2.10 - - [09/Nov/2026:03:01:03 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n')
    run = cli("hunt", clean_log, "--out-dir", tmp_path / "out")
    assert run.returncode == 0
    assert "No threats found" in run.stdout
    assert not (tmp_path / "out" / "block_ips.sh").exists()


def test_allow_keeps_admin_range_out_of_block_script(tmp_path):
    run = cli("hunt", "--demo", "--out-dir", tmp_path, "--allow", "203.0.113.0/24")
    assert run.returncode == 0
    script = (tmp_path / "block_ips.sh").read_text()
    assert "203.0.113." not in script.split("# ---- Undo")[0]
    assert "198.51.100.23" in script
    assert "allowlisted" in run.stdout


@pytest.mark.parametrize("args, message", [
    (["hunt"], "No log files given"),
    (["hunt", "does-not-exist.log"], "Log file not found"),
    (["hunt", "--demo", "--allow", "banana"], "Bad --allow value"),
    (["alert"], "No alert file given"),
    (["alert", "missing.json"], "Alert file not found"),
])
def test_bad_input_exits_2_with_a_clear_message(tmp_path, args, message):
    run = cli(*args, "--out-dir", tmp_path)
    assert run.returncode == 2
    assert message in run.stderr
    assert "Traceback" not in run.stdout + run.stderr


def test_corrupt_alert_json_exits_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json\n{ neither is this")
    run = cli("alert", bad, "--out-dir", tmp_path)
    assert run.returncode == 2 and "Could not read alerts" in run.stderr
    assert "Traceback" not in run.stderr


def test_broken_rule_file_is_reported_with_file_and_rule(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "mine.yml").write_text("- id: my-rule\n  name: MINE\n  title: x\n  type: web\n  severity: high\n"
                                    "  mitre: [T9999]\n  pattern: 'x'\n")
    run = cli("hunt", "--demo", "--rules-dir", rules, "--out-dir", tmp_path)
    assert run.returncode == 2
    assert "my-rule" in run.stderr and "T9999" in run.stderr


def test_user_rule_override_and_custom_rule(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "local.yml").write_text(
        "- id: web-xss\n  enabled: false\n"
        "- id: web-admin-probe\n  name: ADMIN_PROBE\n  title: Admin panel probe\n  type: web\n  severity: low\n"
        "  mitre: [T1595.003]\n  pattern: '^/admin/'\n  tests:\n    match: ['/admin/dashboard']\n")
    run = cli("hunt", "--demo", "--rules-dir", rules, "--out-dir", tmp_path)
    assert run.returncode == 0, run.stderr
    findings = json.loads((tmp_path / "triage_report.json").read_text())["findings"]
    ids = {f["rule_id"] for f in findings}
    assert "web-admin-probe" in ids and "web-xss" not in ids


def test_rules_test_and_list(tmp_path):
    run = cli("rules", "test")
    assert run.returncode == 0 and "rules passed" in run.stdout
    listing = cli("rules", "list", "--type", "event")
    assert "win-dcsync" in listing.stdout and "web-xss" not in listing.stdout
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yml").write_text("- id: web-broken\n  name: BROKEN\n  title: x\n  type: web\n  severity: low\n"
                                   "  pattern: 'abc'\n  tests:\n    match: ['xyz']\n")
    failing = cli("rules", "test", "web-broken", "--rules-dir", rules)
    assert failing.returncode == 1 and "should match: xyz" in failing.stdout


def test_missing_blocklist_is_a_warning_not_a_crash(tmp_path):
    run = cli("hunt", SAMPLES / "auth.log", "--bad-ips", tmp_path / "nope.txt", "--out-dir", tmp_path)
    assert run.returncode == 0
    assert "continuing without it" in run.stderr
    assert "BAD_IP_MATCH" not in run.stdout


def test_invalid_blocklist_entries_are_reported(tmp_path):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("203.0.113.50  # ok\nnot-an-ip[red]  # typo\n")
    run = cli("hunt", SAMPLES / "access.log", "--bad-ips", blocklist, "--out-dir", tmp_path)
    assert run.returncode == 0
    assert "Ignored invalid blocklist entry on line 2: not-an-ip[red]" in run.stderr


def test_cached_feeds_are_loaded_and_reported(tmp_path):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    # Feeds may only list globally routable addresses: the private /8 and the documentation
    # address are refused, so only the public test fixture IP counts.
    (feeds / "test-feed.txt").write_text("# fetched_at: 2026-01-01T00:00:00Z\n9.9.9.9\n10.0.0.0/8\n203.0.113.50\n")
    log = tmp_path / "access.log"
    log.write_text('9.9.9.9 - - [09/Nov/2026:03:01:03 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n')
    run = cli("hunt", log, "--out-dir", tmp_path / "out", feeds_dir=feeds)
    assert run.returncode == 0
    assert "test-feed (1)" in run.stdout
    assert "stale" in run.stdout
    assert "feed: test-feed" in (tmp_path / "out" / "triage_report.txt").read_text()


def test_alert_demo_saves_payloads_and_audit_log(tmp_path):
    run = cli("alert", "--demo", "--out-dir", tmp_path)
    assert run.returncode == 0, run.stderr
    assert "CRITICAL" in run.stdout
    assert len(list((tmp_path / "dry_run").glob("*.json"))) == 3
    audit = json.loads((tmp_path / "alert_results.ndjson").read_text().splitlines()[0])
    assert audit["severity"] == "critical" and audit["escalated"] is True and audit["mitre"] == ["T1105"]


def test_alert_ndjson_with_two_alerts(tmp_path):
    lines = [(SAMPLES / name).read_text().replace("\n", " ") for name in ("dummy_alert.json", "benign_alert.json")]
    ndjson = tmp_path / "alerts.json"
    ndjson.write_text("\n".join(lines) + "\n")
    run = cli("alert", ndjson, "--mock", "--dry-run", "--out-dir", tmp_path)
    assert run.returncode == 0
    assert run.stdout.count("alert enrichment") == 2
    assert len((tmp_path / "alert_results.ndjson").read_text().splitlines()) == 2


def test_alert_without_keys_warns_and_skips(tmp_path):
    run = cli("alert", SAMPLES / "dummy_alert.json", "--out-dir", tmp_path, cwd=tmp_path)  # no .env here
    assert run.returncode == 0
    assert "VT_API_KEY is not set" in run.stderr
    assert "SKIPPED" in run.stdout


def test_works_from_any_directory(tmp_path):
    run = cli("hunt", "--demo", cwd=tmp_path)
    assert run.returncode == 0
    assert (tmp_path / "bluetriage-output" / "triage_report.txt").exists()


def test_main_py_shim_still_works(tmp_path):
    env = {**os.environ, "BLUETRIAGE_FEEDS_DIR": str(tmp_path / "none")}
    run = subprocess.run([sys.executable, str(ROOT / "main.py"), "hunt", "--demo", "--quiet", "--out-dir",
                          str(tmp_path)], capture_output=True, text=True, env=env, timeout=120)
    assert run.returncode == 0, run.stderr


def test_svg_screenshot(tmp_path):
    svg = tmp_path / "shot.svg"
    assert cli("hunt", "--demo", "--out-dir", tmp_path, "--svg", svg).returncode == 0
    assert svg.read_text().startswith("<svg")
