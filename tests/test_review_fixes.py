"""Regression tests for the v2.0.0 pre-release code review: one block per finding."""
import gzip
import json
import os
import subprocess
import sys
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from owltriage.detectors import Analyzer, analyze
from owltriage.intel import BadIPList
from owltriage.log_parser import iter_text_events
from owltriage.pipeline import TriageReport, extract_observables, load_alerts
from owltriage.rules import load_rules

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "owltriage" / "resources" / "samples"
ATTACKER = "203.0.113.9"


def failed(ts: str, ip: str = ATTACKER) -> str:
    return f"{ts} server sshd[1]: Failed password for root from {ip} port 4242 ssh2\n"


def accepted(ts: str, ip: str = ATTACKER) -> str:
    return f"{ts} server sshd[1]: Accepted password for root from {ip} port 4242 ssh2\n"


def rule_ids(*paths, **kwargs):
    return [f.rule_id for f in analyze(paths, window_seconds=600, year=2026, **kwargs).findings]


# 1. "message repeated N times" must not store N copies of the timestamp
def test_repeated_message_lines_use_constant_memory(tmp_path):
    log = tmp_path / "auth.log"
    line = ("Nov 12 10:00:01 server sshd[1]: message repeated 100000 times: "
            f"[ Failed password for root from {ATTACKER} port 4242 ssh2]\n")
    log.write_text(line * 300, encoding="utf-8")
    tracemalloc.start()
    result = analyze([log], window_seconds=600, year=2026)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert result.failed_by_ip[ATTACKER] == 300 * 100_000
    assert "auth-brute-force" in [f.rule_id for f in result.findings]
    assert peak < 30_000_000, f"peak {peak / 1e6:.0f} MB"   # was ~240 MB for these 37 KB


# 2. events from an older file processed after a newer one must not share a window
def test_older_file_after_newer_file_is_not_brute_force(tmp_path):
    new, old = tmp_path / "auth.log", tmp_path / "auth.log.1"
    new.write_text("".join(failed(f"Nov 12 10:00:0{i}") for i in range(1, 4)), encoding="utf-8")
    old.write_text("".join(failed(f"Nov  5 08:00:0{i}") for i in range(1, 4)), encoding="utf-8")
    assert "auth-brute-force" not in rule_ids(new, old)
    assert "auth-brute-force" not in rule_ids(old, new)


def test_old_success_is_not_blamed_on_newer_failures(tmp_path):
    new, old = tmp_path / "auth.log", tmp_path / "auth.log.1"
    new.write_text("".join(failed(f"Nov 12 10:00:0{i}") for i in range(1, 7)), encoding="utf-8")
    old.write_text(accepted("Nov  5 08:00:00"), encoding="utf-8")
    ids = rule_ids(new, old)
    assert "auth-brute-force" in ids                         # the real brute force today
    assert "auth-success-after-brute-force" not in ids       # last week's login is unrelated


def test_in_order_success_after_brute_force_still_detected(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(failed(f"Nov 12 10:00:0{i}") for i in range(1, 7)) + accepted("Nov 12 10:00:09"),
                   encoding="utf-8")
    assert "auth-success-after-brute-force" in rule_ids(log)


# 3. logrotate's .gz files are read, and a damaged one is reported
def test_gzip_rotated_log_gives_the_same_findings(tmp_path):
    plain = SAMPLES / "auth.log"
    packed = tmp_path / "auth.log.2.gz"
    packed.write_bytes(gzip.compress(plain.read_bytes()))
    expected = sorted(f.rule_id for f in analyze([plain], year=2026).findings)
    assert expected and sorted(f.rule_id for f in analyze([packed], year=2026).findings) == expected


def test_truncated_gzip_is_a_warning_not_a_crash(tmp_path):
    packed = tmp_path / "auth.log.3.gz"
    packed.write_bytes(gzip.compress((SAMPLES / "auth.log").read_bytes())[:200])
    result = analyze([packed], year=2026)
    assert any("auth.log.3.gz" in w for w in result.warnings)


# 4. NDJSON lines that are not objects get a clear error
def test_ndjson_with_non_object_lines_is_rejected_clearly(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"id": "1"}\n[1, 2]\n', encoding="utf-8")
    try:
        load_alerts(path)
    except ValueError as exc:
        assert "line 2" in str(exc)
    else:
        raise AssertionError("expected ValueError")


# 5. an Infinity rule level (valid for Python's json) must not crash the report
def test_infinite_rule_level_does_not_crash():
    alert = json.loads('{"id": "1", "rule": {"level": Infinity}}')
    assert TriageReport.from_alert(alert).rule_level == 0


# 6. + 7. a UTF-8 BOM (Windows PowerShell 5) is accepted
def test_alert_file_with_bom_is_read(tmp_path):
    path = tmp_path / "alert.json"
    path.write_bytes(b"\xef\xbb\xbf" + (SAMPLES / "dummy_alert.json").read_bytes())
    assert len(load_alerts(path)) == 1


def test_blocklist_with_bom_keeps_its_first_entry(tmp_path):
    path = tmp_path / "blocklist.txt"
    path.write_bytes(b"\xef\xbb\xbf203.0.113.50  # first line\n198.51.100.7\n")
    blocklist = BadIPList()
    blocklist.load_file(path)
    assert blocklist.lookup("203.0.113.50") and not blocklist.invalid


# 8. nonsense --threshold / --window values are refused
def run_cli(*args):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "COLUMNS": "200"}
    return subprocess.run([sys.executable, "-m", "owltriage", *map(str, args)], capture_output=True,
                          text=True, encoding="utf-8", env=env, timeout=120)


def test_threshold_and_window_must_make_sense(tmp_path):
    for flag, value, hint in (("--threshold", "0", "1 or more"), ("--window", "-5", "0 or more")):
        run = run_cli("hunt", "--demo", flag, value, "--quiet", "--out-dir", tmp_path)
        assert run.returncode == 2 and hint in run.stderr, run.stderr


# 9. IPv6 attackers mentioned only in full_log are enriched
def test_ipv6_in_full_log_becomes_an_observable():
    alert = {"agent": {"ip": "10.0.2.15"},
             "full_log": "Nov 12 03:14:25 web01 sshd[1]: Failed password for root from 2a03:2880:f12f::25de port 22"}
    found, _ = extract_observables(alert)
    assert [o.value for o in found if o.kind == "ip"] == ["2a03:2880:f12f::25de"]   # and no "03:14:25"


# 10. a syslog file that crosses New Year keeps time moving forward
def test_syslog_year_rollover(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(failed("Dec 31 23:59:58") + failed("Jan  1 00:00:03"), encoding="utf-8")
    first, second = list(iter_text_events(log, year=2025))
    assert datetime.fromtimestamp(second.epoch, timezone.utc).year == 2026
    assert 0 < second.epoch - first.epoch < 10


def test_brute_force_across_midnight_on_new_year(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(failed(f"Dec 31 23:59:5{i}") for i in range(3))
                   + "".join(failed(f"Jan  1 00:00:0{i}") for i in range(3)), encoding="utf-8")
    assert "auth-brute-force" in [f.rule_id for f in analyze([log], window_seconds=600, year=2025).findings]


# Property: the brute-force window is exact for time-ordered events and never over-counts otherwise
RULES = load_rules()
failure_stream = st.lists(st.tuples(st.integers(0, 4000), st.integers(1, 5)), min_size=1, max_size=60)


def true_counts(events, window):
    """Reference: for each failure, the failures seen so far (itself included) in [t - window, t]."""
    return [sum(c for t2, c in events[:k + 1] if t - window <= t2 <= t) for k, (t, _) in enumerate(events)]


@settings(max_examples=400, deadline=None)
@given(failure_stream, st.integers(1, 900))
def test_window_count_is_exact_for_ordered_events(events, window):
    events = sorted(events, key=lambda e: e[0])
    analyzer = Analyzer(ruleset=RULES, window_seconds=window)
    got = [analyzer._add_failures("x", float(t), c) for t, c in events]
    assert got == true_counts(events, window)


@settings(max_examples=400, deadline=None)
@given(failure_stream, st.integers(1, 900))
def test_window_count_never_over_counts_in_any_order(events, window):
    analyzer = Analyzer(ruleset=RULES, window_seconds=window)
    for (t, c), truth in zip(events, true_counts(events, window)):
        got = analyzer._add_failures("x", float(t), c)
        assert c <= got <= truth                                   # a false positive needs got > truth
        assert analyzer._recent_failures("x", float(t)) <= truth


def test_progress_bar_follows_a_gzip_log(tmp_path):
    lines = "".join(failed(f"Nov 12 10:{i // 60 % 60:02d}:{i % 60:02d}", f"203.0.113.{i % 50}") for i in range(20000))
    packed = tmp_path / "auth.log.2.gz"
    packed.write_bytes(gzip.compress(lines.encode()))                      # compresses about 20x
    seen = []
    analyze([packed], year=2026, on_progress=lambda p: seen.append((p.events, p.fraction)))
    halfway = next(fraction for events, fraction in seen if events >= 10000)
    assert 0.3 < halfway < 0.7, f"bar shows {halfway:.0%} at half the events"
