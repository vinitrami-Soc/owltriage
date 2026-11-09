"""Option 1, Phase 2: local threat intel (the offline bad_ips.txt blocklist)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class BadIPList:
    """Single IPs and CIDR ranges, each with a human-readable label.

    File format: one entry per line, `#` starts a comment/label:
        203.0.113.50        # SQLi campaign source
        198.51.100.16/28    # botnet range
    """

    addresses: Dict[object, str] = field(default_factory=dict)
    networks: List[Tuple[object, str]] = field(default_factory=list)
    invalid: List[Tuple[int, str]] = field(default_factory=list)

    @classmethod
    def load(cls, path) -> "BadIPList":
        blocklist = cls()
        with Path(path).open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                blocklist.add_line(line, line_no)
        return blocklist

    def add_line(self, line: str, line_no: int = 0) -> None:
        entry, _, comment = line.partition("#")
        entry = entry.strip()
        if not entry:
            return
        label = comment.strip() or "listed in bad_ips.txt"
        try:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                self.networks.append((network, f"{label} [{network}]"))
            else:
                self.addresses[ipaddress.ip_address(entry)] = label
        except ValueError:
            self.invalid.append((line_no, entry))

    def lookup(self, ip: str) -> Optional[str]:
        """Return the label if `ip` is listed (directly or via a range), else None."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr in self.addresses:
            return self.addresses[addr]
        for network, label in self.networks:
            if addr.version == network.version and addr in network:
                return label
        return None

    def __len__(self) -> int:
        return len(self.addresses) + len(self.networks)
