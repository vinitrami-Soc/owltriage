"""Threat feeds (download, parse, safety filters, fast lookup), time windows and machine-readable exports."""
import csv
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests
from hypothesis import given, settings
from hypothesis import strategies as st

from owltriage.detectors import Analyzer, analyze
from owltriage.exporters import write_attack_layer, write_findings_ndjson, write_iocs_csv, write_stix_bundle
from owltriage.feeds import FeedSpec, load_feed_specs, load_feeds_into, parse_feed_text, update_feeds
from owltriage.intel import BadIPList
from owltriage.log_parser import parse_line
from owltriage.rules import load_rules

SAMPLES = Path(__file__).resolve().parent.parent / "owltriage" / "resources" / "samples"


# ---------------------------------------------------------------- feeds
def test_parse_feed_formats():
    text = ("# comment\n; also comment\n// and this\n1.2.3.4\n5.6.7.0/24 # trailing\n8.8.4.4\t7\n"
            "2001:db8::/32\nnot-an-ip\n1.2.3.4-1.2.3.9\n\n")
    entries, rejected = parse_feed_text(text)
    assert entries == ["1.2.3.4", "5.6.7.0/24", "8.8.4.4", "2001:db8::/32"]
    assert rejected == 2


def test_feed_config_is_valid_and_https():
    specs = load_feed_specs()
    assert len({s.id for s in specs}) == len(specs) >= 4
    assert all(s.url.startswith("https://") for s in specs)


@pytest.fixture
def feed_server():
    routes = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = routes.get(self.path, (404, b"nope"))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", routes
    server.shutdown()
    server.server_close()


def session():
    s = requests.Session()
    s.trust_env = False
    return s


def test_update_feeds_end_to_end(feed_server, tmp_path):
    base, routes = feed_server
    routes["/good.txt"] = (200, b"# header\n9.9.9.9\n45.33.0.0/16\n10.0.0.0/8\n127.0.0.1\n0.0.0.0/0\n")
    routes["/html.txt"] = (200, b"<html>maintenance</html>")
    routes["/big.txt"] = (200, b"9.9.9.9\n" * 2000)
    specs = [FeedSpec("good", f"{base}/good.txt"), FeedSpec("html", f"{base}/html.txt"),
             FeedSpec("gone", f"{base}/missing.txt"), FeedSpec("big", f"{base}/big.txt"),
             FeedSpec("off", f"{base}/good.txt", enabled=False)]
    results = {r.id: r for r in update_feeds(specs, tmp_path, session=session(), max_bytes=10_000)}
    assert (results["good"].status, results["good"].entries, results["good"].dropped) == ("updated", 2, 3)
    assert results["html"].status == "failed" and "no usable" in results["html"].detail
    assert results["gone"].detail == "HTTP 404"
    assert results["big"].status == "failed" and "larger than" in results["big"].detail
    assert results["off"].status == "skipped"
    assert not list(tmp_path.glob("*.tmp"))

    blocklist = BadIPList()
    [info] = load_feeds_into(blocklist, tmp_path)
    assert (info.id, info.entries) == ("good", 2) and info.age_days < 0.01 and not info.stale
    assert blocklist.lookup("9.9.9.9") == "feed: good"
    assert blocklist.lookup("45.33.1.2") == "feed: good [45.33.0.0/16]"
    assert blocklist.lookup("10.1.1.1") is None


def test_feeds_can_never_flag_private_or_huge_ranges():
    blocklist = BadIPList()
    for entry in ("10.0.0.0/8", "192.168.0.0/16", "127.0.0.1", "0.0.0.0/0", "1.0.0.0/7", "fe80::/10", "::/0"):
        blocklist.add(entry, "x", "feed", public_only=True)
    assert len(blocklist) == 0 and blocklist.dropped == 7
    local = BadIPList()
    local.add_line("10.0.0.0/8 # my own list may include internal ranges")
    assert local.lookup("10.2.3.4")


@settings(max_examples=200, deadline=None)
@given(st.lists(st.tuples(st.ip_addresses(v=4), st.integers(8, 32)), max_size=30), st.ip_addresses(v=4))
def test_prefix_index_matches_naive_lookup(networks, probe):
    blocklist = BadIPList()
    nets = []
    for addr, prefix in networks:
        net = ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
        nets.append(net)
        blocklist.add(str(net), "x")
    assert (blocklist.lookup(str(probe)) is not None) == any(probe in n for n in nets)


# ---------------------------------------------------------------- time window
FAIL = "Nov  9 03:{m:02d}:{s:02d} web01 sshd[1]: Failed password for root from 203.0.113.5 port 1{m:02d}{s:02d} ssh2"
OK = "Nov  9 03:{m:02d}:00 web01 sshd[1]: Accepted password for root from 203.0.113.5 port 2 ssh2"


def run(lines, window=None):
    analyzer = Analyzer(window_seconds=window)
    for no, line in enumerate(lines, 1):
        analyzer.feed(parse_line(line, no, "t.log", year=2026))
    return {f.rule_id for f in analyzer.finish().findings}


def test_slow_failures_outside_the_window_are_not_brute_force():
    slow = [FAIL.format(m=m * 11, s=0) for m in range(5)]  # one failure every 11 minutes
    assert "auth-brute-force" not in run(slow, window=600)
    assert "auth-brute-force" in run(slow, window=0)  # whole-file counting still sees 5


def test_fast_failures_inside_the_window_are_brute_force():
    fast = [FAIL.format(m=10, s=s) for s in range(5)]
    assert "auth-brute-force" in run(fast, window=600)


def test_compromise_needs_the_success_inside_the_window():
    fast = [FAIL.format(m=10, s=s) for s in range(5)]
    assert "auth-success-after-brute-force" in run(fast + [OK.format(m=12)], window=600)
    assert "auth-success-after-brute-force" not in run(fast + [OK.format(m=59)], window=600)


# ---------------------------------------------------------------- exports
@pytest.fixture(scope="module")
def demo_result():
    result = analyze([SAMPLES / "auth.log", SAMPLES / "access.log", SAMPLES / "windows_security.xml"],
                     BadIPList.load(SAMPLES / "bad_ips.txt"))
    return result, load_rules()


def test_stix_bundle_is_valid_and_deterministic(demo_result, tmp_path):
    result, _ = demo_result
    first = json.loads(write_stix_bundle(result, tmp_path / "a.json").read_text(encoding="utf-8"))
    second = json.loads(write_stix_bundle(result, tmp_path / "b.json").read_text(encoding="utf-8"))
    ids = lambda b: sorted(o["id"] for o in b["objects"] if o["type"] == "indicator")  # noqa: E731
    assert ids(first) == ids(second) and len(ids(first)) == 7
    stix2 = pytest.importorskip("stix2")
    stix2.parse(json.dumps(first), allow_custom=False)


def test_attack_navigator_layer(demo_result, tmp_path):
    result, ruleset = demo_result
    layer = json.loads(write_attack_layer(result, ruleset, tmp_path / "layer.json").read_text(encoding="utf-8"))
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110.003", "T1490", "T1070.001", "T1059.001"} <= ids
    assert all(t["score"] > 0 for t in layer["techniques"])


def test_ndjson_is_ecs_shaped(demo_result, tmp_path):
    result, ruleset = demo_result
    docs = [json.loads(line) for line in write_findings_ndjson(result, ruleset, tmp_path / "f.ndjson").read_text(encoding="utf-8").splitlines()]
    assert len(docs) == len(result.findings)
    compromise = next(d for d in docs if d["rule"]["name"] == "COMPROMISE_SUSPECTED")
    assert compromise["event"]["kind"] == "alert" and compromise["source"]["ip"]
    assert compromise["threat"]["technique"]["name"] == ["Brute Force", "Valid Accounts"]
    assert compromise["@timestamp"].endswith("Z")


def test_ioc_csv(demo_result, tmp_path):
    result, _ = demo_result
    rows = list(csv.DictReader(write_iocs_csv(result, tmp_path / "i.csv").open()))
    assert {r["verdict"] for r in rows} <= {"MALICIOUS", "SUSPICIOUS"}
    assert any(r["ip"] == "198.51.100.77" and "T1110.001" in r["mitre"] for r in rows)


def test_update_feeds_quiet_prints_only_failures(feed_server, tmp_path, monkeypatch, capsys):
    from owltriage.cli import main
    base, routes = feed_server
    routes["/good.txt"] = (200, b"9.9.9.9\n")
    config = tmp_path / "feeds.yml"
    config.write_text(f"- id: good\n  url: {base}/good.txt\n- id: gone\n  url: {base}/missing.txt\n", encoding="utf-8")
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(var, raising=False)              # the fake feed server is on localhost
    argv = ["update-feeds", "--feeds-config", str(config), "--feeds-dir", str(tmp_path / "cache")]
    assert main([*argv, "--quiet"]) == 0                    # one feed worked, so cron sees success
    quiet = capsys.readouterr()
    assert "gone" in quiet.err and "HTTP 404" in quiet.err
    assert quiet.out == "" and "good" not in quiet.err
    assert main(argv) == 0
    assert "good" in capsys.readouterr().out
