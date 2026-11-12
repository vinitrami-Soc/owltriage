"""Pick the right reader for each log file by looking at its content, not just its name."""
from __future__ import annotations

import codecs
import gzip
from pathlib import Path
from typing import Iterator, Optional

from .log_parser import GZIP_MAGIC, LogEvent, iter_text_events
from .windows import iter_evtx, iter_windows_json, iter_windows_xml

EVTX_MAGIC = b"ElfFile\x00"


def detect_format(path) -> str:
    """Return 'evtx', 'windows-xml', 'jsonl' or 'text'."""
    path = Path(path)
    with path.open("rb") as handle:
        head = handle.read(4096)
    if head.startswith(GZIP_MAGIC):  # rotated logs: look at what is inside
        try:
            with gzip.open(path, "rb") as packed:
                head = packed.read(4096)
        except (OSError, EOFError):
            return "text"  # the text reader reports the damage
        return "jsonl" if head.lstrip().startswith(b"{") else "text"
    if head.startswith(EVTX_MAGIC) or path.suffix.lower() == ".evtx":
        return "evtx"
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = head.decode("utf-16", errors="ignore")
    else:
        text = head.decode("utf-8", errors="ignore")
    text = text.lstrip("﻿ \t\r\n")
    if text.startswith("<"):
        return "windows-xml"
    if text.startswith("{"):
        return "jsonl"
    return "text"


def iter_events(path, year: Optional[int] = None) -> Iterator[LogEvent]:
    kind = detect_format(path)
    if kind == "evtx":
        return iter_evtx(path)
    if kind == "windows-xml":
        return iter_windows_xml(path)
    if kind == "jsonl":
        return iter_windows_json(path, year)
    return iter_text_events(path, year)
