"""Timestamp parsing for every log format owltriage reads (used for time-window correlation)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

_MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|[+-]\d{2}:?\d{2})?")
_SYSLOG = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})")
_APACHE = re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?")


def _tz(text: Optional[str]) -> timezone:
    if not text or text == "Z":
        return timezone.utc
    sign = -1 if text[0] == "-" else 1
    digits = text[1:].replace(":", "")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:4])))


def parse_timestamp(text: Optional[str], default_year: Optional[int] = None) -> Optional[datetime]:
    """Parse ISO 8601 / Windows SystemTime, Apache `09/Nov/2026:03:16:01 +0000` and syslog
    `Nov  9 03:11:45` (no year: `default_year`, else the current year). Naive times are UTC.
    Returns None for anything unparseable instead of raising.
    """
    if not text:
        return None
    text = text.strip()
    try:
        m = _ISO.match(text)
        if m:
            micro = int((m.group(7) or "0")[:6].ljust(6, "0"))
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                            int(m.group(5)), int(m.group(6)), micro, tzinfo=_tz(m.group(8)))
        m = _APACHE.match(text)
        if m:
            return datetime(int(m.group(3)), _MONTHS[m.group(2).lower()], int(m.group(1)), int(m.group(4)),
                            int(m.group(5)), int(m.group(6)), tzinfo=_tz(m.group(7)))
        m = _SYSLOG.match(text)
        if m:
            year = default_year or datetime.now(timezone.utc).year
            return datetime(year, _MONTHS[m.group(1).lower()], int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
    except (KeyError, ValueError, OverflowError):
        return None
    return None


@lru_cache(maxsize=8192)  # many log lines share the same second
def to_epoch(text: Optional[str], default_year: Optional[int] = None) -> Optional[float]:
    parsed = parse_timestamp(text, default_year)
    return parsed.timestamp() if parsed else None


def iso_utc(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
