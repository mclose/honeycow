"""Source-IP exemption list — REFUSE queries from known scanner ranges.

A name-blind defense layer that complements the qname-based exemption
list. Queries from IPs in this list get REFUSED regardless of qname,
qtype, or qclass — so when a research scanner (Shadowserver, Censys,
ASERT/Netscout, Driftnet, etc.) fingerprints us via *any* probe, we
return the same boring REFUSED a regular off-zone authoritative would.

This is the layer that keeps us off "open resolver" reports even when
scanners stop using their canonical probe zones and start fingerprinting
via `TXT google.com` or `TXT version.bind` — a class of probe the qname
list cannot catch.

File format: one IP address or CIDR per line; '#' starts a comment;
blank lines are ignored. Both IPv4 and IPv6 are supported.

Reload semantics match `squatter.exemptions.ExemptionList`: parse
failures leave the existing list intact (fail-open), and SIGHUP triggers
a reload via the honey_ns signal handler.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

log = logging.getLogger("honey_ns")

_IPv4Net = ipaddress.IPv4Network
_IPv6Net = ipaddress.IPv6Network


class SourceExemptionList:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._v4: list[_IPv4Net] = []
        self._v6: list[_IPv6Net] = []
        if path is not None:
            self.load()

    def load(self) -> tuple[int, int]:
        """Re-read the source exemption file. Returns (old_count, new_count).

        On any parse failure, leaves the existing lists unchanged.
        """
        if self.path is None:
            return (len(self), len(self))
        old_count = len(self)
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("source exemption file unreadable: %s", exc)
            return (old_count, old_count)

        new_v4: list[_IPv4Net] = []
        new_v6: list[_IPv6Net] = []
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError as exc:
                log.warning(
                    "source exemption parse error %r: %s — keeping old list",
                    raw_line, exc,
                )
                return (old_count, old_count)
            if isinstance(net, _IPv4Net):
                new_v4.append(net)
            else:
                new_v6.append(net)

        self._v4 = new_v4
        self._v6 = new_v6
        new_count = len(self)
        log.info("source exemption list reloaded: %d -> %d", old_count, new_count)
        return (old_count, new_count)

    def is_exempt(self, src_ip: str) -> bool:
        if not src_ip:
            return False
        if not self._v4 and not self._v6:
            return False
        try:
            ip = ipaddress.ip_address(src_ip)
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in net for net in self._v4)
        return any(ip in net for net in self._v6)

    def __len__(self) -> int:
        return len(self._v4) + len(self._v6)
