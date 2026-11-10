"""Download and cache free IP threat feeds (`owltriage update-feeds`).

Feeds are stored as plain text in the cache directory and loaded automatically
by `owltriage hunt`, so the hunt itself stays offline: run update-feeds from
cron once a day, hunt as often as you like.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import requests
import yaml

from . import __version__
from .intel import BadIPList, is_public_range
from .timeutil import iso_utc, to_epoch
from .utils import clean

FEEDS_FILE = Path(__file__).resolve().parent / "resources" / "feeds.yml"
MAX_FEED_BYTES = 25_000_000
STALE_AFTER_DAYS = 7
_FEED_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
_SPLIT = re.compile(r"[\s,;#]")


def default_feeds_dir() -> Path:
    if os.environ.get("OWLTRIAGE_FEEDS_DIR"):
        return Path(os.environ["OWLTRIAGE_FEEDS_DIR"])
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return cache / "owltriage" / "feeds"


@dataclass
class FeedSpec:
    id: str
    url: str
    name: str = ""
    homepage: str = ""
    description: str = ""
    enabled: bool = True


@dataclass
class FeedResult:
    id: str
    status: str  # updated | failed | skipped
    entries: int = 0
    dropped: int = 0
    detail: str = ""


@dataclass
class FeedInfo:
    id: str
    entries: int
    fetched_at: Optional[str]
    age_days: Optional[float]

    @property
    def stale(self) -> bool:
        return self.age_days is None or self.age_days > STALE_AFTER_DAYS


def load_feed_specs(path: Optional[Path] = None) -> List[FeedSpec]:
    with Path(path or FEEDS_FILE).open(encoding="utf-8") as handle:
        items = yaml.safe_load(handle) or []
    specs = []
    for item in items:
        if not isinstance(item, dict) or not _FEED_ID.match(str(item.get("id", ""))):
            raise ValueError(f"feed entries need an 'id' in lowercase-kebab-case: {item!r}")
        url = str(item.get("url", ""))
        if not url.startswith(("https://", "http://")):
            raise ValueError(f"feed {item['id']}: url must be http(s)")
        specs.append(FeedSpec(id=item["id"], url=url, name=str(item.get("name", "")),
                              homepage=str(item.get("homepage", "")), description=str(item.get("description", "")),
                              enabled=bool(item.get("enabled", True))))
    return specs


def parse_feed_text(text: str) -> Tuple[List[str], int]:
    """Return (valid IP/CIDR entries, number of unparseable lines). Accepts '1.2.3.4', '1.2.3.0/24',
    'IP<tab>count' (IPsum) and lines with trailing comments; skips '#', ';' and '//' comments."""
    entries: List[str] = []
    rejected = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = _SPLIT.split(line, 1)[0]
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            rejected += 1
            continue
        single = network.prefixlen == network.max_prefixlen
        entries.append(str(network.network_address) if single else str(network))
    return entries, rejected


def _download(session: requests.Session, url: str, timeout: float, max_bytes: int) -> str:
    with session.get(url, timeout=timeout, stream=True) as response:
        response.raise_for_status()
        chunks, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"feed is larger than {max_bytes // 1_000_000} MB; refusing")
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def update_feeds(specs: Sequence[FeedSpec], feeds_dir: Optional[Path] = None,
                 session: Optional[requests.Session] = None, timeout: float = 30,
                 only: Sequence[str] = (), max_bytes: int = MAX_FEED_BYTES) -> List[FeedResult]:
    feeds_dir = Path(feeds_dir or default_feeds_dir())
    feeds_dir.mkdir(parents=True, exist_ok=True)
    session = session or requests.Session()
    if hasattr(session, "headers"):
        session.headers["User-Agent"] = f"owltriage/{__version__} (+feed updater)"
    results = []
    for spec in specs:
        if only and spec.id not in only:
            continue
        if not spec.enabled and spec.id not in only:
            results.append(FeedResult(spec.id, "skipped", detail="disabled in feeds config"))
            continue
        try:
            text = _download(session, spec.url, timeout, max_bytes)
        except (requests.RequestException, ValueError) as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            reason = f"HTTP {status}" if status else clean(f"{type(exc).__name__}: {exc}", 120)
            results.append(FeedResult(spec.id, "failed", detail=reason))
            continue
        entries, rejected = parse_feed_text(text)
        kept = [e for e in entries if is_public_range(ipaddress.ip_network(e))]
        if not kept:
            results.append(FeedResult(spec.id, "failed", detail="no usable IP entries (format changed?)"))
            continue
        target = feeds_dir / f"{spec.id}.txt"
        tmp = target.with_suffix(".tmp")
        header = [f"# owltriage feed: {spec.id}", f"# source: {spec.url}",
                  f"# fetched_at: {iso_utc(datetime.now(timezone.utc).timestamp())}", f"# entries: {len(kept)}"]
        tmp.write_text("\n".join(header + kept) + "\n", encoding="utf-8")
        os.replace(tmp, target)  # atomic: a hunt never reads a half-written feed
        results.append(FeedResult(spec.id, "updated", entries=len(kept), dropped=len(entries) - len(kept),
                                  detail=f"{rejected} unparseable line(s)" if rejected else ""))
    return results


def load_feeds_into(blocklist: BadIPList, feeds_dir: Optional[Path] = None) -> List[FeedInfo]:
    """Load every cached feed into `blocklist` (labels 'feed: <id>'). Missing dir = no feeds."""
    feeds_dir = Path(feeds_dir or default_feeds_dir())
    if not feeds_dir.is_dir():
        return []
    infos = []
    now = datetime.now(timezone.utc).timestamp()
    for path in sorted(feeds_dir.glob("*.txt")):
        feed_id = path.stem
        fetched_at = None
        before = blocklist.sources[feed_id]
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("# fetched_at:"):
                    fetched_at = line.split(":", 1)[1].strip()
                if line.startswith("#") or not line.strip():
                    continue
                blocklist.add(line.strip(), f"feed: {feed_id}", feed_id, public_only=True)
        epoch = to_epoch(fetched_at)
        age = (now - epoch) / 86400 if epoch else None
        infos.append(FeedInfo(feed_id, blocklist.sources[feed_id] - before, fetched_at, age))
    return infos
