"""Text log ingestion: Linux auth.log / secure (sshd, sudo, useradd, ...) and Apache/Nginx access logs.

Files are read line by line (streaming), so a multi-GB log never has to fit in RAM.
Every line becomes a `LogEvent`; Windows logs produce the same `LogEvent` type
(see windows.py), so all detection rules work across sources.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterator, List, Optional
from urllib.parse import unquote

from .timeutil import to_epoch

MAX_LINE = 65_536  # longer "lines" are junk or an attack on the parser; keep the head only

# Four dot-separated 1-3 digit groups that are not part of a longer dotted string
# such as a version number (1.2.3.4.5). Matches are validated with `ipaddress`.
IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

SYSLOG_TIMESTAMP = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S*)\s"
)
REPEATED = re.compile(r"message repeated (\d+) times")

# The username is attacker-controlled: `ssh "x from 6.6.6.6 port 1"@server`
# writes that text into the log. The greedy `.*` makes the regex use the LAST
# "from <ip> port <n>", which sshd itself appends, so a crafted username cannot
# make us blame (and later block) a spoofed IP.
_SSH_TAIL = r" from (?P<ip>\S+) port \d+"
SSH_RULES = (
    ("auth_failure", re.compile(
        r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
        r"(?:invalid user )?(?P<user>.*)" + _SSH_TAIL)),
    ("auth_success", re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>.*)" + _SSH_TAIL)),
    ("auth_invalid_user", re.compile(r"Invalid user (?P<user>.*)" + _SSH_TAIL)),
)
SUDO_COMMAND = re.compile(r"\bsudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?\bCOMMAND=(?P<cmd>.*)$")

ACCESS_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: [^"]*)?" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)


@dataclass
class LogEvent:
    source: str
    line_no: int
    raw: str
    # auth_failure | auth_success | auth_invalid_user | http_request | process | network | event | other
    kind: str = "other"
    log_type: str = "text"  # text | windows
    service: Optional[str] = None  # ssh, rdp, network, sudo, ...
    timestamp: Optional[str] = None
    epoch: Optional[float] = None
    ip: Optional[str] = None  # the actor (SSH/HTTP client, logon source, or connection destination)
    direction: Optional[str] = None  # "outbound" when `ip` is a destination this host connected to
    user: Optional[str] = None
    repeat: int = 1  # syslog "message repeated N times"
    method: Optional[str] = None
    path: Optional[str] = None  # URL-decoded request target
    status: Optional[int] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    command: Optional[str] = None  # sudo COMMAND=, Windows 4688 / Sysmon 1 CommandLine
    event_id: Optional[int] = None
    channel: str = ""
    provider: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    ips: List[str] = field(default_factory=list)  # every valid IP in the event


@lru_cache(maxsize=65536)  # logs repeat the same few IPs; parsing them was the #1 hotspot
def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Return a canonical IP string, or None if `value` is not an IP address."""
    if not value:
        return None
    candidate = value.strip().strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def extract_ips(text: str) -> List[str]:
    """All valid IPv4 addresses in `text`, de-duplicated, in order of appearance."""
    seen: List[str] = []
    for match in IPV4_CANDIDATE.finditer(text):
        ip = normalize_ip(match.group(0))
        if ip and ip not in seen:
            seen.append(ip)
    return seen


def url_decode(value: str, rounds: int = 3) -> str:
    """Percent-decode repeatedly so double-encoded payloads (%2527 -> ') show up.

    '+' is left alone because it is also a valid base64 character; web rules
    check a '+'-as-space variant separately.
    """
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def parse_line(line: str, line_no: int = 0, source: str = "-", year: Optional[int] = None) -> LogEvent:
    raw = line.rstrip("\r\n")[:MAX_LINE]
    event = LogEvent(source=source, line_no=line_no, raw=raw, ips=extract_ips(raw))

    web = ACCESS_LOG.match(raw)
    if web and normalize_ip(web["ip"]):
        event.kind = "http_request"
        event.service = "http"
        event.ip = normalize_ip(web["ip"])
        event.timestamp = web["ts"]
        event.epoch = to_epoch(web["ts"])
        event.user = None if web["user"] == "-" else web["user"]
        event.method = web["method"]
        event.path = url_decode(web["path"])
        event.status = int(web["status"])
        event.user_agent = web["agent"]
        event.referrer = web["referrer"]
        if event.ip not in event.ips:
            event.ips.insert(0, event.ip)
        return event

    ts = SYSLOG_TIMESTAMP.match(raw)
    if ts:
        event.timestamp = ts["ts"]
        event.epoch = to_epoch(ts["ts"], year)
    repeated = REPEATED.search(raw)
    if repeated:
        event.repeat = max(1, min(int(repeated.group(1)), 100_000))

    for kind, pattern in SSH_RULES:
        match = pattern.search(raw)
        if not match:
            continue
        ip = normalize_ip(match["ip"])
        if ip:
            event.kind = kind
            event.service = "ssh"
            event.ip = ip
            event.user = match["user"]
            if ip not in event.ips:
                event.ips.append(ip)
        break
    else:
        sudo = SUDO_COMMAND.search(raw)
        if sudo:
            event.kind = "process"
            event.service = "sudo"
            event.user = sudo["user"]
            event.command = sudo["cmd"].strip()
    return event


def iter_text_events(path, year: Optional[int] = None) -> Iterator[LogEvent]:
    """Yield one `LogEvent` per non-empty line without loading the whole file."""
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if line.strip():
                yield parse_line(line, line_no, path.name, year)


def iter_events(path, year: Optional[int] = None) -> Iterator[LogEvent]:
    """Any supported log file (format auto-detected). Kept here for backwards compatibility."""
    from .sources import iter_events as _iter_events
    return _iter_events(path, year=year)
