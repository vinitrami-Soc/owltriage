"""Integration tests over real HTTP.

A local server stands in for VirusTotal, AbuseIPDB, Discord, Slack and TheHive,
so the live code path (requests.Session, headers, JSON bodies, status codes,
timeouts) runs exactly as it would in production, just without the internet.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

from owltriage import enrichment
from owltriage.config import Settings
from owltriage.pipeline import TriagePipeline, load_alerts

DATA = Path(__file__).resolve().parent.parent / "owltriage" / "resources" / "samples"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
MOCK = json.loads((Path(__file__).resolve().parent.parent / "owltriage" / "resources" / "mock_intel.json").read_text())


class FakeSOC:
    """Records every request and answers like the real services would."""

    def __init__(self):
        self.requests = []
        self.routes = {}  # (method, path) -> (status, body) or callable
        self.delay = 0.0

    def handle(self, handler, method):
        length = int(handler.headers.get("Content-Length") or 0)
        raw = handler.rfile.read(length) if length else b""
        body = json.loads(raw) if raw else None
        path = handler.path.split("?", 1)[0]
        self.requests.append({"method": method, "path": handler.path, "headers": dict(handler.headers), "json": body})
        if self.delay:
            time.sleep(self.delay)
        route = self.routes.get((method, path), (404, {"error": {"code": "NotFoundError"}}))
        status, payload = route(body) if callable(route) else route
        data = b"" if payload is None else json.dumps(payload).encode()
        try:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(data)))
            handler.end_headers()
            handler.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client already gave up (timeout tests)

    def find(self, method, path_prefix):
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(path_prefix)]


@pytest.fixture
def soc(monkeypatch):
    fake = FakeSOC()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            fake.handle(self, "GET")

        def do_POST(self):
            fake.handle(self, "POST")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    fake.base = base
    monkeypatch.setattr(enrichment, "VT_API", f"{base}/api/v3")
    monkeypatch.setattr(enrichment, "ABUSEIPDB_API", f"{base}/api/v2")
    yield fake
    server.shutdown()
    server.server_close()


def session():
    s = requests.Session()
    s.trust_env = False  # don't send localhost traffic through the sandbox proxy
    return s


def serve_real_intel(soc):
    soc.routes[("GET", "/api/v3/ip_addresses/203.0.113.5")] = (200, MOCK["virustotal"]["ip"]["203.0.113.5"])
    soc.routes[("GET", f"/api/v3/files/{EICAR}")] = (200, MOCK["virustotal"]["hash"][EICAR])
    soc.routes[("GET", "/api/v2/check")] = (200, MOCK["abuseipdb"]["203.0.113.5"])
    soc.routes[("POST", "/discord")] = (204, None)
    soc.routes[("POST", "/slack")] = (200, None)
    soc.routes[("POST", "/api/v1/case")] = (201, {"_id": "~4096", "number": 42})
    soc.routes[("POST", "/api/v1/case/~4096/observable")] = (201, [{"_id": "~1"}])


def live_settings(soc, **overrides):
    values = dict(vt_api_key="vt-key", abuseipdb_api_key="abuse-key",
                  discord_webhook_url=f"{soc.base}/discord", slack_webhook_url=f"{soc.base}/slack",
                  thehive_url=f"{soc.base}/", thehive_api_key="hive-key", vt_requests_per_minute=0, timeout=2)
    values.update(overrides)
    return Settings(**values)


def test_full_live_pipeline_over_http(soc, tmp_path):
    serve_real_intel(soc)
    report = TriagePipeline(live_settings(soc), out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "dummy_alert.json")[0])

    assert report.severity == "critical"
    assert report.actions == [
        ("Discord webhook", "sent", "HTTP 204"),
        ("Slack webhook", "sent", "HTTP 200"),
        ("TheHive case", "created", "case #42 (~4096), 2/2 observables added"),
    ]

    vt_calls = soc.find("GET", "/api/v3/")
    assert {c["headers"]["x-apikey"] for c in vt_calls} == {"vt-key"}
    abuse = soc.find("GET", "/api/v2/check")[0]
    assert abuse["headers"]["Key"] == "abuse-key"
    assert "ipAddress=203.0.113.5" in abuse["path"] and "maxAgeInDays=90" in abuse["path"]
    assert all(c["headers"]["User-Agent"].startswith("owltriage/") for c in soc.requests)

    case = soc.find("POST", "/api/v1/case")[0]
    assert case["headers"]["Authorization"] == "Bearer hive-key"
    assert case["json"]["severity"] == 4 and case["json"]["flag"] is True
    assert "mitre:T1105" in case["json"]["tags"]
    observables = [r["json"] for r in soc.find("POST", "/api/v1/case/~4096/observable")]
    assert {(o["dataType"], o["data"], o["ioc"]) for o in observables} == {
        ("ip", "203.0.113.5", True), ("hash", EICAR, True)}

    discord = soc.find("POST", "/discord")[0]
    assert discord["headers"]["Content-Type"] == "application/json"
    assert discord["json"]["embeds"][0]["title"].startswith("🚨 CRITICAL")


def test_benign_alert_sends_nothing(soc, tmp_path):
    soc.routes[("GET", "/api/v2/check")] = (200, MOCK["abuseipdb"]["192.0.2.10"])
    soc.routes[("GET", "/api/v3/ip_addresses/192.0.2.10")] = (200, MOCK["virustotal"]["ip"]["192.0.2.10"])
    report = TriagePipeline(live_settings(soc), out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "benign_alert.json")[0])
    assert report.severity == "low"
    assert soc.find("POST", "/") == []  # no webhook, no case


def test_thehive_auth_failure_is_reported(soc, tmp_path):
    serve_real_intel(soc)
    soc.routes[("POST", "/api/v1/case")] = (401, {"type": "AuthenticationError"})
    report = TriagePipeline(live_settings(soc), out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "dummy_alert.json")[0])
    assert ("TheHive case", "failed", "HTTP 401") in report.actions
    assert soc.find("POST", "/api/v1/case/") == []  # no observables for a case that does not exist


def test_thehive_partial_observable_failure(soc, tmp_path):
    serve_real_intel(soc)
    calls = []

    def flaky(body):
        calls.append(body)
        return (201, [{"_id": "~1"}]) if len(calls) == 1 else (500, {"type": "InternalError"})

    soc.routes[("POST", "/api/v1/case/~4096/observable")] = flaky
    report = TriagePipeline(live_settings(soc), out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "dummy_alert.json")[0])
    assert ("TheHive case", "created", "case #42 (~4096), 1/2 observables added") in report.actions


def test_slow_api_times_out_cleanly(soc, tmp_path):
    serve_real_intel(soc)
    soc.delay = 1.5
    settings = live_settings(soc, timeout=0.3, discord_webhook_url="", slack_webhook_url="", thehive_url="")
    started = time.monotonic()
    report = TriagePipeline(settings, out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "dummy_alert.json")[0])
    assert time.monotonic() - started < 5
    assert {r.verdict for r in report.results} == {"ERROR"}
    assert all(r.error == "network error (ReadTimeout)" for r in report.results)
    assert not report.flagged


def test_unreachable_host_is_reported_not_raised(tmp_path):
    settings = Settings(discord_webhook_url="http://127.0.0.1:9/hook", thehive_url="http://127.0.0.1:9",
                        thehive_api_key="k", timeout=1)
    report = TriagePipeline(settings, mock=True, out_dir=tmp_path, session=session()).run(
        load_alerts(DATA / "dummy_alert.json")[0])
    statuses = {name: (status, detail) for name, status, detail in report.actions}
    assert statuses["Discord webhook"] == ("failed", "network error (ConnectionError)")
    assert statuses["TheHive case"] == ("failed", "network error (ConnectionError)")


def test_vt_quota_exhausted(soc, tmp_path):
    soc.routes[("GET", "/api/v3/ip_addresses/203.0.113.5")] = (429, {"error": {"code": "QuotaExceededError"}})
    client = enrichment.VirusTotalClient("k", 5, session=session(), requests_per_minute=0)
    result = client.lookup("ip", "203.0.113.5")
    assert result.error == "HTTP 429: rate limit / daily quota exceeded"


def test_api_returning_html_instead_of_json(soc):
    soc.routes[("GET", "/api/v2/check")] = (502, None)
    result = enrichment.AbuseIPDBClient("k", 50, session=session()).check("203.0.113.5")
    assert result.verdict == "ERROR" and result.error.startswith("HTTP 502")
