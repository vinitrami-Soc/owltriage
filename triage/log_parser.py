"""Option 1, Phase 1: data ingestion.

Reads log files line by line (streaming, so a multi-GB log never has to fit in
RAM) and turns each line into a `LogEvent` with the IP address, username and
request pulled out by regular expressions.

Supported formats:
  * Linux auth.log / secure (OpenSSH via syslog)
  * Apache / Nginx "combined" access logs
Any other line is still scanned for IPv4 addresses, so nothing is silently ignored.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterator, List, Optional
from urllib.parse import unquote

# Four dot-separated 1-3 digit groups that are not part of a longer dotted string
# such as a version number (1.2.3.4.5). Matches are validated with `ipaddress`
# afterwards, so 999.1.1.1 is rejected.
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
    ("ssh_failed", re.compile(
        r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
        r"(?:invalid user )?(?P<user>.*)" + _SSH_TAIL)),
    ("ssh_accepted", re.compile(
        r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>.*)" + _SSH_TAIL)),
    ("ssh_invalid_user", re.compile(r"Invalid user (?P<user>.*)" + _SSH_TAIL)),
)

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
    kind: str = "other"  # ssh_failed | ssh_accepted | ssh_invalid_user | http_request | other
    timestamp: Optional[str] = None
    ip: Optional[str] = None  # the actor: SSH client or HTTP client
    user: Optional[str] = None
    repeat: int = 1  # syslog "message repeated N times"
    method: Optional[str] = None
    path: Optional[str] = None  # URL-decoded request target
    status: Optional[int] = None
    user_agent: Optional[str] = None
    ips: List[str] = field(default_factory=list)  # every valid IP on the line


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

    '+' is left alone because it is also a valid base64 character; the detectors
    check a '+'-as-space variant separately.
    """
    for _ in range(rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def parse_line(line: str, line_no: int = 0, source: str = "-") -> LogEvent:
    raw = line.rstrip("\r\n")
    event = LogEvent(source=source, line_no=line_no, raw=raw, ips=extract_ips(raw))

    web = ACCESS_LOG.match(raw)
    if web and normalize_ip(web["ip"]):
        event.kind = "http_request"
        event.ip = normalize_ip(web["ip"])
        event.timestamp = web["ts"]
        event.user = None if web["user"] == "-" else web["user"]
        event.method = web["method"]
        event.path = url_decode(web["path"])
        event.status = int(web["status"])
        event.user_agent = web["agent"]
        if event.ip not in event.ips:
            event.ips.insert(0, event.ip)
        return event

    ts = SYSLOG_TIMESTAMP.match(raw)
    if ts:
        event.timestamp = ts["ts"]
    repeated = REPEATED.search(raw)
    if repeated:
        event.repeat = max(1, int(repeated.group(1)))

    for kind, pattern in SSH_RULES:
        match = pattern.search(raw)
        if not match:
            continue
        ip = normalize_ip(match["ip"])
        if ip:
            event.kind = kind
            event.ip = ip
            event.user = match["user"]
            if ip not in event.ips:
                event.ips.append(ip)
        break
    return event


def iter_events(path) -> Iterator[LogEvent]:
    """Yield one `LogEvent` per non-empty line without loading the whole file."""
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, 1):
            if line.strip():
                yield parse_line(line, line_no, path.name)
