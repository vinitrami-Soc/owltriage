"""Local threat intel: your own blocklist files plus downloaded threat feeds.

Lookups are indexed by prefix length, so checking an IP against 100,000 feed
entries costs at most ~33 dictionary lookups instead of a linear scan.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def is_public_range(network) -> bool:
    """Feeds may only list globally routable ranges no wider than /8 (IPv4) or /16 (IPv6),
    so a broken or malicious feed can never flag your LAN, loopback or half the internet."""
    return network.is_global and network.prefixlen >= (8 if network.version == 4 else 16)


class BadIPList:
    """IPs and CIDR ranges, each with a human-readable label.

    File format (one entry per line, `#` starts the label):
        203.0.113.50        # SQLi campaign source
        198.51.100.16/28    # botnet range
    """

    def __init__(self) -> None:
        self._exact: Dict[Tuple[int, int], str] = {}  # (version, int) -> label
        self._networks: Dict[Tuple[int, int], Dict[int, str]] = {}  # (version, prefixlen) -> {net int: label}
        self.invalid: List[Tuple[int, str]] = []
        self.dropped = 0  # feed entries refused because they are private/reserved or absurdly broad
        self.sources: Counter = Counter()

    @classmethod
    def load(cls, path, source: str = "local") -> "BadIPList":
        blocklist = cls()
        blocklist.load_file(path, source)
        return blocklist

    def load_file(self, path, source: str = "local") -> None:
        with Path(path).open(encoding="utf-8", errors="replace") as handle:
            for line_no, line in enumerate(handle, 1):
                self.add_line(line, line_no, source)

    def add_line(self, line: str, line_no: int = 0, source: str = "local") -> None:
        entry, _, comment = line.partition("#")
        entry = entry.strip()
        if not entry:
            return
        label = comment.strip() or ("listed in bad_ips.txt" if source == "local" else f"feed: {source}")
        if not self.add(entry, label, source):
            self.invalid.append((line_no, entry))

    def add(self, entry: str, label: str, source: str = "local", public_only: bool = False) -> bool:
        """Add an IP or CIDR. With public_only (used for feeds), private/reserved ranges and
        anything broader than /8 (IPv4) or /16 (IPv6) are refused, so a bad feed can't flag your LAN."""
        try:
            network = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            return False
        if public_only and not is_public_range(network):
            self.dropped += 1
            return True
        if network.prefixlen == network.max_prefixlen:
            self._exact[(network.version, int(network.network_address))] = label
        else:
            label = f"{label} [{network}]"
            self._networks.setdefault((network.version, network.prefixlen), {})[int(network.network_address)] = label
        self.sources[source] += 1
        return True

    def lookup(self, ip: str) -> Optional[str]:
        """Return the label if `ip` is listed (directly or via a range), else None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        value, bits = int(addr), addr.max_prefixlen
        label = self._exact.get((addr.version, value))
        if label:
            return label
        for (version, prefixlen), networks in self._networks.items():
            if version == addr.version:
                masked = (value >> (bits - prefixlen)) << (bits - prefixlen)
                if masked in networks:
                    return networks[masked]
        return None

    def __len__(self) -> int:
        return len(self._exact) + sum(len(n) for n in self._networks.values())
