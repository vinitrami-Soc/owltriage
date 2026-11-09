"""Report files, terminal rendering and .env configuration."""
import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from triage.config import load_settings
from triage.defense import plan_blocks
from triage.detectors import analyze
from triage.intel import BadIPList
from triage.reporting import render_hunt, write_json_report, write_text_report

DATA = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(scope="module")
def sample():
    result = analyze([DATA / "auth.log", DATA / "access.log"], BadIPList.load(DATA / "bad_ips.txt"))
    rules, skipped = plan_blocks(result.findings)
    return result, rules, skipped


def test_sample_story_is_fully_detected(sample):
    """Regression guard for the attack story in data/: every planted attack must be found."""
    result, rules, _ = sample
    found = {(f.rule, f.ip) for f in result.findings}
    assert {("COMPROMISE_SUSPECTED", "203.0.113.5"), ("SSH_BRUTE_FORCE", "198.51.100.23"),
            ("BAD_IP_MATCH", "192.0.2.77"), ("PATH_TRAVERSAL", "192.0.2.77"),
            ("SQL_INJECTION", "203.0.113.50"), ("XSS", "203.0.113.88"),
            ("C2_INDICATOR", "203.0.113.99")} <= found
    verdicts = {v["ip"]: v["verdict"] for v in result.ip_verdicts()}
    for ip in ("192.168.1.10", "192.168.1.25", "192.168.1.40", "192.0.2.10"):
        assert verdicts[ip] == "CLEAN", f"false positive on {ip}"
    assert len(rules) == 6


def test_text_report_counts_match(sample, tmp_path):
    result, rules, skipped = sample
    text = write_text_report(result, rules, skipped, tmp_path / "r.txt").read_text()
    assert "Attacks / findings detected : 18" in text
    assert "critical 1, high 13, medium 3, low 1" in text
    assert "Malicious IPs               : 5" in text
    assert "iptables -A OUTPUT -d 203.0.113.99 -j DROP" in text


def test_json_report_is_machine_readable(sample, tmp_path):
    result, rules, _ = sample
    data = json.loads(write_json_report(result, rules, tmp_path / "r.json").read_text())
    assert data["stats"]["failed_ssh_logins"] == 15
    assert {"rule", "severity", "ip", "evidence"} <= set(data["findings"][0])
    assert data["block_rules"][0]["command"].startswith("iptables -A")


def test_terminal_output_colors_malicious_red_and_clean_green(sample):
    result, rules, skipped = sample
    console = Console(record=True, file=io.StringIO(), width=160, force_terminal=True)
    render_hunt(console, result, rules, skipped, outputs={})
    html = console.export_html(inline_styles=True)
    assert "MALICIOUS" in html and "CLEAN" in html
    red = console.get_style("bold red").color.get_truecolor()
    green = console.get_style("bold green").color.get_truecolor()
    assert f"#{red.red:02x}{red.green:02x}{red.blue:02x}" in html
    assert f"#{green.red:02x}{green.green:02x}{green.blue:02x}" in html


def test_env_file_is_loaded_and_environment_wins(tmp_path, monkeypatch):
    for name in ("VT_API_KEY", "VT_MALICIOUS_THRESHOLD", "THEHIVE_VERIFY_TLS", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    env = tmp_path / ".env"
    env.write_text("VT_API_KEY=from-file\nVT_MALICIOUS_THRESHOLD=9\nTHEHIVE_VERIFY_TLS=false\n"
                   "ABUSEIPDB_API_KEY=from-file\n")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "from-environment")
    settings = load_settings(env)
    assert settings.vt_api_key == "from-file"
    assert settings.abuseipdb_api_key == "from-environment"
    assert settings.vt_threshold == 9
    assert settings.thehive_verify_tls is False


def test_bad_number_in_env_gives_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_MALICIOUS_THRESHOLD", "five")
    with pytest.raises(SystemExit, match="VT_MALICIOUS_THRESHOLD must be a whole number"):
        load_settings(tmp_path / "missing.env")
