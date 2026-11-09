"""End-to-end tests: run main.py as a real subprocess, the way a user (or cron) would."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAIN = ROOT / "main.py"
SECRET_VARS = ("VT_API_KEY", "ABUSEIPDB_API_KEY", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL",
               "THEHIVE_URL", "THEHIVE_API_KEY")


def cli(*args, cwd=None):
    env = {k: v for k, v in os.environ.items() if k not in SECRET_VARS}
    env["COLUMNS"] = "200"
    return subprocess.run([sys.executable, str(MAIN), *map(str, args)], capture_output=True, text=True,
                          cwd=cwd or ROOT, env=env, timeout=120)


def test_hunt_writes_every_output(tmp_path):
    run = cli("hunt", "--out-dir", tmp_path)
    assert run.returncode == 0, run.stderr
    assert "COMPROMISE_SUSPECTED" in run.stdout
    report = json.loads((tmp_path / "triage_report.json").read_text())
    assert len(report["findings"]) == 18
    assert report["stats"]["findings_by_severity"]["critical"] == 1
    assert "Attacks / findings detected : 18" in (tmp_path / "triage_report.txt").read_text()
    script = tmp_path / "block_ips.sh"
    assert subprocess.run(["bash", "-n", str(script)]).returncode == 0
    assert os.access(script, os.X_OK)


def test_fail_on_gives_nonzero_exit_for_cron(tmp_path):
    assert cli("hunt", "--out-dir", tmp_path, "--fail-on", "critical").returncode == 1
    clean_log = tmp_path / "clean.log"
    clean_log.write_text("Nov  9 03:00:14 web01 sshd[1]: Accepted publickey for ops from 192.168.1.10 port 5 ssh2\n")
    assert cli("hunt", clean_log, "--out-dir", tmp_path / "o", "--fail-on", "low").returncode == 0


def test_clean_log_produces_no_block_script(tmp_path):
    clean_log = tmp_path / "clean.log"
    clean_log.write_text('192.0.2.10 - - [09/Nov/2026:03:01:03 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n')
    run = cli("hunt", clean_log, "--out-dir", tmp_path / "out")
    assert run.returncode == 0
    assert "No threats found" in run.stdout
    assert not (tmp_path / "out" / "block_ips.sh").exists()


def test_allow_keeps_admin_range_out_of_block_script(tmp_path):
    run = cli("hunt", "--out-dir", tmp_path, "--allow", "203.0.113.0/24")
    assert run.returncode == 0
    script = (tmp_path / "block_ips.sh").read_text()
    assert "203.0.113." not in script.split("# ---- Undo")[0]
    assert "198.51.100.23" in script
    assert "allowlisted" in run.stdout


@pytest.mark.parametrize("args, message", [
    (["hunt", "does-not-exist.log"], "Log file not found"),
    (["hunt", "--allow", "banana"], "Bad --allow value"),
    (["alert", "missing.json"], "Alert file not found"),
])
def test_bad_input_exits_2_with_a_clear_message(tmp_path, args, message):
    run = cli(*args, "--out-dir", tmp_path)
    assert run.returncode == 2
    assert message in run.stdout
    assert "Traceback" not in run.stdout + run.stderr


def test_corrupt_alert_json_exits_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not json\n{ neither is this")
    run = cli("alert", bad, "--out-dir", tmp_path)
    assert run.returncode == 2 and "Could not read alerts" in run.stdout
    assert "Traceback" not in run.stderr


def test_missing_blocklist_is_a_warning_not_a_crash(tmp_path):
    run = cli("hunt", "--bad-ips", tmp_path / "nope.txt", "--out-dir", tmp_path)
    assert run.returncode == 0
    assert "continuing without it" in run.stdout
    assert "BAD_IP_MATCH" not in run.stdout


def test_alert_mock_dry_run_saves_three_payloads(tmp_path):
    run = cli("alert", "--mock", "--dry-run", "--out-dir", tmp_path)
    assert run.returncode == 0, run.stderr
    assert "CRITICAL" in run.stdout
    assert len(list((tmp_path / "dry_run").glob("*.json"))) == 3


def test_alert_ndjson_with_two_alerts(tmp_path):
    lines = [(ROOT / "data" / name).read_text().replace("\n", " ") for name in ("dummy_alert.json", "benign_alert.json")]
    ndjson = tmp_path / "alerts.json"
    ndjson.write_text("\n".join(lines) + "\n")
    run = cli("alert", ndjson, "--mock", "--dry-run", "--out-dir", tmp_path)
    assert run.returncode == 0
    assert run.stdout.count("Option 2: API-driven alert pipeline") == 2
    assert "CRITICAL" in run.stdout and "LOW" in run.stdout


def test_alert_without_keys_warns_and_skips(tmp_path):
    run = cli("alert", "--out-dir", tmp_path, cwd=tmp_path)  # cwd without a .env
    assert run.returncode == 0
    assert "VT_API_KEY is not set" in run.stdout
    assert "SKIPPED" in run.stdout


def test_works_from_any_directory(tmp_path):
    run = cli("hunt", "--out-dir", tmp_path / "out", cwd=tmp_path)
    assert run.returncode == 0
    assert (tmp_path / "out" / "triage_report.txt").exists()


def test_svg_screenshot(tmp_path):
    svg = tmp_path / "shot.svg"
    assert cli("hunt", "--out-dir", tmp_path, "--svg", svg).returncode == 0
    assert svg.read_text().startswith("<svg")


def test_invalid_blocklist_entries_are_reported(tmp_path):
    blocklist = tmp_path / "bad.txt"
    blocklist.write_text("203.0.113.50  # ok\nnot-an-ip[red]  # typo\n")
    run = cli("hunt", "--bad-ips", blocklist, "--out-dir", tmp_path)
    assert run.returncode == 0
    assert "Ignored invalid blocklist entry on line 2: not-an-ip[red]" in run.stdout
