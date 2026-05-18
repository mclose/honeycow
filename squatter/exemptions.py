"""Exemption-list loader for honeycow.

A simple text file: one zone or name per line, '#' starts a comment,
blank lines are ignored. Each entry matches the name itself and all
subnames, so listing `example.com` exempts `target.example.com` too.

The file is loaded at startup and on SIGHUP (see honey_ns.main). Reload
is atomic: parse failures leave the existing set unchanged.
"""

from __future__ import annotations

import logging
from pathlib import Path

import dns.exception
import dns.name

log = logging.getLogger("honey_ns")


class ExemptionList:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._exempt: set[dns.name.Name] = set()
        if path is not None:
            self.load()

    def load(self) -> tuple[int, int]:
        """Re-read the exemption file. Returns (old_count, new_count).

        On any parse failure, leaves the existing set unchanged.
        """
        if self.path is None:
            return (len(self._exempt), len(self._exempt))
        old_count = len(self._exempt)
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("exemption file unreadable: %s", exc)
            return (old_count, old_count)

        new_set: set[dns.name.Name] = set()
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                name = dns.name.from_text(
                    line if line.endswith(".") else line + "."
                )
            except dns.exception.DNSException as exc:
                log.warning("exemption parse error %r: %s — keeping old list", raw_line, exc)
                return (old_count, old_count)
            new_set.add(name)

        self._exempt = new_set
        log.info("exemption list reloaded: %d -> %d", old_count, len(new_set))
        return (old_count, len(new_set))

    def is_exempt(self, qname: dns.name.Name) -> bool:
        if not self._exempt:
            return False
        if qname in self._exempt:
            return True
        for exempt_name in self._exempt:
            if qname.is_subdomain(exempt_name):
                return True
        return False

    def __len__(self) -> int:
        return len(self._exempt)
