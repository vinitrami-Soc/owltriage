"""Windows event logs: wevtutil XML exports, .evtx files and JSON lines (Winlogbeat or flat).

    wevtutil qe Security /f:xml > security.xml        # export on the Windows box
    owltriage hunt security.xml                       # or Security.evtx with `pip install owltriage[evtx]`

All XML goes through defusedxml (no DTDs, entity expansion or external
entities): event logs are attacker-influenced input.
"""
from __future__ import annotations

import codecs
import contextlib
import io
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from defusedxml.ElementTree import fromstring, iterparse

from .log_parser import LogEvent, normalize_ip, parse_line
from .timeutil import to_epoch
from .utils import clean

LOGON_SERVICE = {"2": "interactive", "3": "network", "7": "unlock", "8": "network", "10": "rdp", "11": "cached"}
IP_FIELDS = ("IpAddress", "SourceIp", "DestinationIp", "SourceAddress", "DestAddress", "ClientAddress",
             "SourceNetworkAddress")


class SourceError(Exception):
    """A log file could not be read (missing optional dependency, refused or corrupt content)."""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _usable_ip(value: Optional[str]) -> Optional[str]:
    ip = normalize_ip(value)
    if not ip:
        return None
    addr = ipaddress.ip_address(ip)
    return None if addr.is_loopback or addr.is_unspecified else ip


# -- records -----------------------------------------------------------------
def record_from_element(event) -> Dict[str, Any]:
    """<Event> element -> {event_id, provider, channel, computer, time, fields}."""
    record: Dict[str, Any] = {"event_id": None, "provider": "", "channel": "", "computer": "", "time": None,
                              "fields": {}}
    fields: Dict[str, str] = record["fields"]
    for child in event:
        name = _local(child.tag)
        if name == "System":
            for item in child:
                item_name = _local(item.tag)
                if item_name == "EventID":
                    with contextlib.suppress(ValueError):
                        record["event_id"] = int((item.text or "").strip())
                elif item_name == "Provider":
                    record["provider"] = item.get("Name", "")
                elif item_name == "Channel":
                    record["channel"] = (item.text or "").strip()
                elif item_name == "Computer":
                    record["computer"] = (item.text or "").strip()
                elif item_name == "TimeCreated":
                    record["time"] = item.get("SystemTime")
        elif name in ("EventData", "UserData"):
            unnamed = 0
            for item in child.iter():
                if item is child:
                    continue
                item_name = _local(item.tag)
                if item_name == "Data":
                    key = item.get("Name")
                    if not key:
                        unnamed += 1
                        key = f"Data{unnamed}"
                    fields[key] = (item.text or "").strip()
                elif len(item) == 0:  # UserData leaf, e.g. LogFileCleared/SubjectUserName
                    fields[item_name] = (item.text or "").strip()
    return record


def record_from_json(obj: Any) -> Optional[Dict[str, Any]]:
    """Winlogbeat/Elastic (`winlog.*`), EvtxECmd-style or flat JSON -> record, or None if not Windows."""
    if not isinstance(obj, dict):
        return None
    winlog = obj.get("winlog") if isinstance(obj.get("winlog"), dict) else {}
    event = obj.get("event") if isinstance(obj.get("event"), dict) else {}
    event_id = (winlog.get("event_id") or obj.get("EventID") or obj.get("EventId") or obj.get("event_id")
                or event.get("code"))
    if isinstance(event_id, dict):  # {"#text": "4625", ...} style
        event_id = event_id.get("#text") or event_id.get("value")
    try:
        event_id = int(str(event_id).strip())
    except (TypeError, ValueError):
        return None

    data = winlog.get("event_data") or obj.get("EventData") or obj.get("event_data")
    if not isinstance(data, dict):
        data = {k: v for k, v in obj.items() if isinstance(v, (str, int, float))}
    fields = {str(k): "" if v is None else str(v) for k, v in data.items() if not isinstance(v, (dict, list))}
    return {
        "event_id": event_id,
        "provider": str(winlog.get("provider_name") or obj.get("ProviderName") or obj.get("Provider") or ""),
        "channel": str(winlog.get("channel") or obj.get("Channel") or ""),
        "computer": str(winlog.get("computer_name") or obj.get("Computer") or ""),
        "time": obj.get("@timestamp") or obj.get("TimeCreated") or obj.get("SystemTime") or obj.get("timestamp"),
        "fields": fields,
    }


def event_from_record(record: Dict[str, Any], source: str, number: int) -> LogEvent:
    """Map a Windows record onto the common LogEvent so every rule type applies to it."""
    fields: Dict[str, str] = record["fields"]
    event_id = record["event_id"]
    provider = record.get("provider") or ""
    sysmon = "sysmon" in provider.lower()
    summary = " ".join(f"{k}={clean(v, 80)}" for k, v in fields.items() if v and v != "-")
    raw = f"[{record.get('channel') or provider or 'Windows'} {event_id}] {record.get('computer', '')} {summary}"
    time = record.get("time")
    event = LogEvent(source=source, line_no=number, raw=raw[:4000], kind="event", log_type="windows",
                     timestamp=str(time) if time else None, epoch=to_epoch(str(time)) if time else None,
                     event_id=event_id, channel=record.get("channel") or "", provider=provider, fields=fields,
                     host=(str(record.get("computer") or "")[:64] or None))

    ips: List[str] = []
    for name in IP_FIELDS:
        ip = _usable_ip(fields.get(name))
        if ip and ip not in ips:
            ips.append(ip)
    event.ips = ips

    if not sysmon and event_id in (4624, 4625, 4768, 4771):
        ip = _usable_ip(fields.get("IpAddress"))
        logon_type = str(fields.get("LogonType", "")).strip()
        kerberos_ok = str(fields.get("Status", "")).strip().lower() in ("0x0", "0")
        if event_id == 4624:
            outcome = "auth_success" if logon_type in ("3", "10") else None
        elif event_id == 4768:  # TGT request: failure 0x6 = unknown user (kerbrute-style user enumeration)
            outcome = "auth_success" if kerberos_ok else "auth_failure"
        else:  # 4625 logon failure, 4771 Kerberos pre-authentication failed
            outcome = "auth_failure"
        if ip and outcome:
            event.kind = outcome
            event.ip = ip
            event.user = fields.get("TargetUserName") or None
            event.service = "kerberos" if event_id in (4768, 4771) else LOGON_SERVICE.get(logon_type, "windows")
    elif event_id == 4104 and "powershell" in provider.lower():
        # PowerShell Script Block Logging: the de-obfuscated script that actually ran
        event.kind = "process"
        event.service = "powershell"
        event.command = fields.get("ScriptBlockText") or None
    elif (not sysmon and event_id == 4688) or (sysmon and event_id == 1):
        event.kind = "process"
        event.service = "windows"
        event.command = fields.get("CommandLine") or fields.get("NewProcessName") or fields.get("Image")
        event.user = fields.get("SubjectUserName") or fields.get("User") or None
    elif sysmon and event_id == 3:
        event.kind = "network"
        event.ip = _usable_ip(fields.get("DestinationIp"))
        event.direction = "outbound"
        event.user = fields.get("User") or None
    return event


# -- file readers --------------------------------------------------------------
class _ChunkReader(io.RawIOBase):
    def __init__(self, chunks: Iterator[bytes]) -> None:
        self._chunks, self._buffer = chunks, b""

    def readable(self) -> bool:
        return True

    def readinto(self, target) -> int:
        while not self._buffer:
            try:
                self._buffer = next(self._chunks)
            except StopIteration:
                return 0
        size = min(len(target), len(self._buffer))
        target[:size], self._buffer = self._buffer[:size], self._buffer[size:]
        return size


def _xml_chunks(path: Path) -> Iterator[bytes]:
    """wevtutil prints many <Event> roots back to back; wrap them in one root element.
    UTF-16 exports (PowerShell 5 redirection) are re-encoded to UTF-8 on the fly."""
    yield b"<owltriage-events>"
    with path.open("rb") as handle:
        head = handle.read(65536)
        if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            decoder = codecs.getincrementaldecoder("utf-16")()
            head = decoder.decode(head).encode("utf-8")

            def reencode() -> Iterator[bytes]:
                for block in iter(lambda: handle.read(65536), b""):
                    yield decoder.decode(block).encode("utf-8")
                yield decoder.decode(b"", final=True).encode("utf-8")

            rest: Iterator[bytes] = reencode()
        else:
            rest = iter(lambda: handle.read(65536), b"")
        head = head.lstrip(codecs.BOM_UTF8).lstrip()
        if head.startswith(b"<?xml"):
            head = head[head.find(b"?>") + 2:]
        yield head
        yield from rest
    yield b"</owltriage-events>"


def iter_windows_xml(path) -> Iterator[LogEvent]:
    path = Path(path)
    reader = io.BufferedReader(_ChunkReader(_xml_chunks(path)))
    stack: list = []
    count = 0
    try:
        for action, element in iterparse(reader, events=("start", "end")):
            if action == "start":
                stack.append(element)
                continue
            stack.pop()
            if _local(element.tag) == "Event":
                count += 1
                yield event_from_record(record_from_element(element), path.name, count)
                if stack:
                    stack[-1].remove(element)  # keep memory flat on huge exports
    except (ValueError, SyntaxError) as exc:  # defusedxml refusals are ValueErrors; expat's ParseError is a SyntaxError
        raise SourceError(f"{path.name}: stopped after {count} events: {clean(exc, 120)}") from None


def iter_evtx(path) -> Iterator[LogEvent]:
    path = Path(path)
    try:
        from evtx import PyEvtxParser
    except ImportError:
        raise SourceError(
            f"{path.name}: reading .evtx needs the optional 'evtx' package: pip install 'owltriage[evtx]'. "
            "Or export on Windows with: wevtutil qe Security /f:xml > security.xml") from None
    try:
        parser = PyEvtxParser(str(path))
    except Exception as exc:  # the Rust parser raises its own error types
        raise SourceError(f"{path.name}: not a readable .evtx file ({clean(exc, 100)})") from None
    bad = good = 0
    for number, record in enumerate(parser.records(), 1):
        try:
            element = fromstring(record["data"])
        except Exception:  # corrupt record or refused XML: skip it, keep going
            bad += 1
            continue
        good += 1
        yield event_from_record(record_from_element(element), path.name, number)
    if bad:
        raise SourceError(f"{path.name}: skipped {bad} unreadable record(s)")
    if not good:
        # Some evtx versions read a damaged file as "no records" instead of raising: never stay silent.
        raise SourceError(f"{path.name}: no event records found (empty or damaged .evtx?)")


def iter_windows_json(path, year: Optional[int] = None) -> Iterator[LogEvent]:
    """JSON lines. Lines that are not Windows events are still parsed as plain text."""
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = record_from_json(json.loads(line))
            except (ValueError, RecursionError):
                record = None
            if record:
                yield event_from_record(record, path.name, number)
            else:
                yield parse_line(line, number, path.name, year)
