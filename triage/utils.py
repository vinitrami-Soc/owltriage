"""Small helpers shared by both pipelines."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}

# C0/C1 control characters (ANSI escapes, newlines, ...) plus the Unicode
# bidi/zero-width characters used in "Trojan Source"-style display tricks.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")


def clean(text: object, max_len: int = 160) -> str:
    """Make attacker-controlled text safe to print or put in a report.

    Log lines are written by whoever sends traffic to your server, so they can
    contain ANSI escape sequences (which can rewrite your terminal) or newlines
    (which can forge extra report lines). Replace those and cap the length.
    """
    if text is None:
        return ""
    value = _UNSAFE_CHARS.sub(" ", str(text))
    if max_len and len(value) > max_len:
        value = value[: max_len - 1] + "…"
    return value


def rel(path) -> str:
    """Show a path relative to the current directory when possible (shorter, no home dir leak)."""
    path = Path(path)
    try:
        return str(path.resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def max_severity(levels: Iterable[str]) -> Optional[str]:
    levels = list(levels)
    return max(levels, key=SEVERITY_RANK.__getitem__) if levels else None


def severity_rank(level: Optional[str]) -> int:
    return -1 if level is None else SEVERITY_RANK[level]


def verdict_for(severity: Optional[str]) -> str:
    """Map the worst finding for an IP to the verdict shown in the reports."""
    rank = severity_rank(severity)
    if rank >= SEVERITY_RANK["high"]:
        return "MALICIOUS"
    if rank == SEVERITY_RANK["medium"]:
        return "SUSPICIOUS"
    if rank >= 0:
        return "REVIEW"
    return "CLEAN"
