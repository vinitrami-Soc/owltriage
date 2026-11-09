"""Settings from environment variables / `.env`.

API keys never live in code: copy `.env.example` to `.env` (git-ignored) and fill it in.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _str(name: str) -> str:
    return os.getenv(name, "").strip()


def _int(name: str, default: int) -> int:
    raw = _str(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"Config error: {name} must be a whole number (got {raw!r})") from None


def _bool(name: str, default: bool) -> bool:
    raw = _str(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass
class Settings:
    # repr=False keeps secrets out of logs/tracebacks if a Settings object is printed.
    vt_api_key: str = field(default="", repr=False)
    abuseipdb_api_key: str = field(default="", repr=False)
    discord_webhook_url: str = field(default="", repr=False)
    slack_webhook_url: str = field(default="", repr=False)
    thehive_url: str = ""
    thehive_api_key: str = field(default="", repr=False)
    thehive_verify_tls: bool = True
    vt_threshold: int = 5  # roadmap: "If VT score > 5 then alert"
    abuseipdb_threshold: int = 50  # confidence % at or above which an IP counts as malicious
    vt_requests_per_minute: int = 4  # VirusTotal free tier limit
    timeout: float = 15.0


def load_settings(env_file: Optional[Path] = None) -> Settings:
    """Read `.env` (project root by default) and the process environment.

    Variables already set in the environment win over the `.env` file.
    """
    load_dotenv(env_file or PROJECT_ROOT / ".env")
    return Settings(
        vt_api_key=_str("VT_API_KEY"),
        abuseipdb_api_key=_str("ABUSEIPDB_API_KEY"),
        discord_webhook_url=_str("DISCORD_WEBHOOK_URL"),
        slack_webhook_url=_str("SLACK_WEBHOOK_URL"),
        thehive_url=_str("THEHIVE_URL"),
        thehive_api_key=_str("THEHIVE_API_KEY"),
        thehive_verify_tls=_bool("THEHIVE_VERIFY_TLS", True),
        vt_threshold=_int("VT_MALICIOUS_THRESHOLD", 5),
        abuseipdb_threshold=_int("ABUSEIPDB_CONFIDENCE_THRESHOLD", 50),
        vt_requests_per_minute=_int("VT_REQUESTS_PER_MINUTE", 4),
    )
