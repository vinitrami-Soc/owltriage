import json
from pathlib import Path

import pytest

from bluetriage.config import Settings
from bluetriage.enrichment import AbuseIPDBClient, RateLimiter, VirusTotalClient
from bluetriage.pipeline import TriagePipeline, extract_observables, load_alerts

DATA = Path(__file__).resolve().parent.parent / "bluetriage" / "resources" / "samples"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class NoNetwork:
    """A requests.Session stand-in that fails the test if anything touches the network."""
    headers = {}

    def get(self, *args, **kwargs):
        raise AssertionError("network GET in a test")

    def post(self, *args, **kwargs):
        raise AssertionError("network POST in a test")


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class FakeSession:
    headers = {}

    def __init__(self, status=200, body=None):
        self.response = FakeResponse(status, body or {})
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def alert(name="dummy_alert.json"):
    return load_alerts(DATA / name)[0]


def test_observables_from_wazuh_alert():
    found, skipped = extract_observables(alert())
    assert [(o.kind, o.value) for o in found] == [("ip", "203.0.113.5"), ("hash", EICAR)]
    assert skipped == []  # agent.ip is not in full_log, so nothing else to skip


def test_internal_and_agent_ips_are_not_sent_to_apis():
    found, skipped = extract_observables({"agent": {"ip": "10.0.2.15"},
                                          "data": {"srcip": "10.0.2.15", "dstip": "192.168.5.5"}})
    assert found == []
    assert [ip for ip, _ in skipped] == ["10.0.2.15", "192.168.5.5"]


def test_mock_pipeline_escalates_malicious_alert(tmp_path):
    pipeline = TriagePipeline(Settings(), mock=True, dry_run=True, out_dir=tmp_path, session=NoNetwork())
    report = pipeline.run(alert())

    assert report.severity == "critical" and report.flagged
    assert {r.verdict for r in report.results} == {"MALICIOUS"}
    assert [r.command() for r in report.block_rules] == ["iptables -A INPUT -s 203.0.113.5 -j DROP"]
    assert [(a, s) for a, s, _ in report.actions] == [
        ("Discord webhook", "dry-run"), ("Slack webhook", "dry-run"), ("TheHive case", "dry-run")]

    discord = json.loads(next(tmp_path.glob("dry_run/discord_*.json")).read_text())
    assert discord["allowed_mentions"] == {"parse": []}
    assert len(discord["embeds"][0]["fields"]) <= 25
    case = json.loads(next(tmp_path.glob("dry_run/thehive_*.json")).read_text())
    assert case["case"]["severity"] == 4
    assert {o["data"] for o in case["observables"]} == {"203.0.113.5", EICAR}


def test_mock_pipeline_does_not_escalate_benign_alert(tmp_path):
    pipeline = TriagePipeline(Settings(), mock=True, out_dir=tmp_path, session=NoNetwork())
    report = pipeline.run(alert("benign_alert.json"))
    assert report.severity == "low" and not report.flagged
    assert {s for _, s, _ in report.actions} == {"not needed"}


def test_missing_keys_are_reported_not_crashed(tmp_path):
    report = TriagePipeline(Settings(), out_dir=tmp_path, session=NoNetwork()).run(alert())
    assert {r.verdict for r in report.results} == {"SKIPPED"}
    assert not report.flagged


def test_virustotal_response_parsing_and_threshold():
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 6, "suspicious": 1, "harmless": 50,
                                                            "undetected": 20}, "country": "NL"}}}
    session = FakeSession(200, body)
    result = VirusTotalClient("key", 5, session=session, requests_per_minute=0).lookup("ip", "203.0.113.5")
    assert (result.score, result.out_of, result.flagged) == (6, 77, True)
    url, kwargs = session.calls[0]
    assert url.endswith("/ip_addresses/203.0.113.5") and kwargs["headers"]["x-apikey"] == "key"


@pytest.mark.parametrize("status, text", [(401, "invalid or missing API key"), (429, "rate limit")])
def test_virustotal_errors_are_explained(status, text):
    result = VirusTotalClient("key", 5, session=FakeSession(status), requests_per_minute=0).lookup("hash", EICAR)
    assert result.verdict == "ERROR" and text in result.error


def test_virustotal_unknown_hash_is_not_an_error():
    result = VirusTotalClient("key", 5, session=FakeSession(404), requests_per_minute=0).lookup("hash", EICAR)
    assert result.verdict == "UNKNOWN" and result.error is None


def test_abuseipdb_parsing():
    session = FakeSession(200, {"data": {"abuseConfidenceScore": 87, "totalReports": 12, "countryCode": "NL"}})
    result = AbuseIPDBClient("key", 50, session=session).check("203.0.113.5")
    assert (result.score, result.flagged) == (87, True)
    assert session.calls[0][1]["params"]["ipAddress"] == "203.0.113.5"


def test_rate_limiter_waits_when_quota_is_used():
    now, slept = [0.0], []
    limiter = RateLimiter(2, 60, clock=lambda: now[0], sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)))
    limiter.wait()
    limiter.wait()
    limiter.wait()
    assert slept == [60.0]


def test_webhook_failure_never_leaks_the_url(tmp_path):
    secret = "https://discord.com/api/webhooks/123/SECRET-TOKEN"
    settings = Settings(discord_webhook_url=secret)
    pipeline = TriagePipeline(settings, mock=True, out_dir=tmp_path, session=FakeSession(500), create_case=False)
    report = pipeline.run(alert())
    discord = next(a for a in report.actions if a[0] == "Discord webhook")
    assert discord[1] == "failed" and "SECRET" not in discord[2]


def test_ndjson_alert_file(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text('{"id": "1"}\n{"id": "2"}\n')
    assert [a["id"] for a in load_alerts(path)] == ["1", "2"]


def test_settings_repr_hides_secrets():
    assert "topsecret" not in repr(Settings(vt_api_key="topsecret", discord_webhook_url="topsecret"))


@pytest.mark.parametrize("malicious, flagged", [(5, False), (6, True)])
def test_virustotal_threshold_boundary(malicious, flagged):
    """Roadmap rule is 'VT score > 5': exactly 5 must NOT escalate."""
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious, "harmless": 60}}}}
    result = VirusTotalClient("key", 5, session=FakeSession(200, body), requests_per_minute=0).lookup("ip", "203.0.113.5")
    assert result.flagged is flagged
