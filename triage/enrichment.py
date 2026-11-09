"""Option 2, Phase 2: threat enrichment via VirusTotal (v3) and AbuseIPDB (v2).

With `mock_data` the clients answer from `data/mock_intel.json` instead of the
network. Those fixtures use the real API response layout, so the exact same
parsing code runs in demo mode and in production.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

import requests

from .utils import clean

VT_API = "https://www.virustotal.com/api/v3"
VT_GUI = "https://www.virustotal.com/gui"
ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2"
MOCK_FILE = Path(__file__).resolve().parent.parent / "data" / "mock_intel.json"
_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}")


@dataclass
class IntelResult:
    provider: str
    indicator: str
    kind: str  # "ip" | "hash"
    score: Optional[int] = None  # VT: malicious engine count, AbuseIPDB: confidence 0-100
    out_of: Optional[int] = None  # VT: engines that answered, AbuseIPDB: 100
    flagged: bool = False  # score crossed the configured threshold
    found: bool = False
    summary: str = ""
    link: str = ""
    error: Optional[str] = None
    skipped: bool = False  # provider not configured
    mock: bool = False

    @property
    def verdict(self) -> str:
        if self.skipped:
            return "SKIPPED"
        if self.error:
            return "ERROR"
        if not self.found:
            return "UNKNOWN"
        if self.flagged:
            return "MALICIOUS"
        return "SUSPICIOUS" if self.score else "CLEAN"

    @property
    def score_text(self) -> str:
        if self.skipped or self.error:
            return "-"
        if not self.found:
            return "not found"
        if self.provider == "AbuseIPDB":
            return f"{self.score}% confidence"
        return f"{self.score}/{self.out_of} engines"


def load_mock_responses(path: Path = MOCK_FILE) -> dict:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


class RateLimiter:
    """At most `max_calls` per `period` seconds (VirusTotal free tier: 4/minute)."""

    def __init__(self, max_calls: int, period: float = 60.0,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.max_calls, self.period = max_calls, period
        self._clock, self._sleep = clock, sleep
        self._calls: deque = deque()

    def wait(self) -> None:
        if self.max_calls <= 0:
            return
        now = self._clock()
        while self._calls and now - self._calls[0] >= self.period:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            delay = self.period - (now - self._calls[0])
            if delay > 0:
                self._sleep(delay)
            self._calls.popleft()
            now = self._clock()
        self._calls.append(now)


def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _http_problem(status: int, body: dict) -> str:
    hints = {401: "invalid or missing API key", 403: "API key not allowed to do this",
             404: "not found", 422: "API rejected the indicator", 429: "rate limit / daily quota exceeded"}
    if status in hints:
        return f"HTTP {status}: {hints[status]}"
    error = body.get("error") if isinstance(body, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return f"HTTP {status}: {clean(code, 60) if code else 'unexpected response'}"


class _Client:
    provider = "?"

    def __init__(self, api_key: str = "", threshold: int = 0, session: Optional[requests.Session] = None,
                 timeout: float = 15.0, mock_data: Optional[dict] = None) -> None:
        self.api_key = api_key
        self.threshold = threshold
        self.session = session or requests.Session()
        self.timeout = timeout
        self.mock_data = mock_data

    @property
    def mock(self) -> bool:
        return self.mock_data is not None

    def _get(self, url: str, headers: dict, params: Optional[dict], mock_key: Tuple[str, ...]) -> Tuple[int, dict]:
        if self.mock_data is not None:
            node = self.mock_data
            for key in mock_key:
                node = node.get(key, {}) if isinstance(node, dict) else {}
            return (200, node) if node else (404, {})
        response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
        try:
            body = response.json()
        except ValueError:
            body = {}
        return response.status_code, body if isinstance(body, dict) else {}


class VirusTotalClient(_Client):
    provider = "VirusTotal"

    def __init__(self, *args, requests_per_minute: int = 4, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.limiter = RateLimiter(requests_per_minute)

    def lookup(self, kind: str, value: str) -> IntelResult:
        result = IntelResult(self.provider, value, kind, mock=self.mock)
        if kind == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                result.error = "not a valid IP"
                return result
            path, result.link = f"ip_addresses/{value}", f"{VT_GUI}/ip-address/{value}"
        elif kind == "hash" and _HASH.fullmatch(value):
            path, result.link = f"files/{value}", f"{VT_GUI}/file/{value}"
        else:
            result.error = "unsupported indicator"
            return result

        if not self.mock:
            self.limiter.wait()
        try:
            status, body = self._get(f"{VT_API}/{path}",
                                     {"x-apikey": self.api_key, "accept": "application/json"},
                                     None, ("virustotal", kind, value))
        except requests.RequestException as exc:
            result.error = f"network error ({type(exc).__name__})"
            return result

        if status == 404:
            result.summary = "never seen by VirusTotal"
            return result
        if status != 200:
            result.error = _http_problem(status, body)
            return result

        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = _to_int(stats.get("malicious"))
        suspicious = _to_int(stats.get("suspicious"))
        result.found = True
        result.score = malicious
        result.out_of = sum(_to_int(v) for v in stats.values())
        result.flagged = malicious > self.threshold

        parts = []
        if kind == "hash":
            label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"))
            parts += [label, attrs.get("meaningful_name"), attrs.get("type_description")]
        else:
            parts += [attrs.get("country"), attrs.get("as_owner")]
            if attrs.get("reputation") is not None:
                parts.append(f"reputation {attrs.get('reputation')}")
        if suspicious:
            parts.append(f"{suspicious} suspicious")
        result.summary = clean(", ".join(str(p) for p in parts if p), 140)
        return result


class AbuseIPDBClient(_Client):
    provider = "AbuseIPDB"

    def check(self, ip: str) -> IntelResult:
        result = IntelResult(self.provider, ip, "ip", out_of=100, mock=self.mock,
                             link=f"https://www.abuseipdb.com/check/{ip}")
        try:
            status, body = self._get(f"{ABUSEIPDB_API}/check",
                                     {"Key": self.api_key, "Accept": "application/json"},
                                     {"ipAddress": ip, "maxAgeInDays": "90"}, ("abuseipdb", ip))
        except requests.RequestException as exc:
            result.error = f"network error ({type(exc).__name__})"
            return result

        if status == 404 and self.mock:
            status, body = 200, {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        if status != 200:
            result.error = _http_problem(status, body)
            return result

        data = body.get("data") or {}
        result.found = True
        result.score = _to_int(data.get("abuseConfidenceScore"))
        result.flagged = result.score >= self.threshold
        parts = [f"{_to_int(data.get('totalReports'))} reports (90d)", data.get("countryCode"),
                 data.get("isp"), data.get("usageType")]
        result.summary = clean(", ".join(str(p) for p in parts if p), 140)
        return result
