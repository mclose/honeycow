#!/usr/bin/env python3
"""Shared parse + classify core for HoneyCow telemetry.

This module is the single source of truth for turning raw HoneyCow events
(and UFW log lines) into classified, bucketable data. It is imported by
two consumers with deliberately separate lifecycles:

  * `tools/morning_report.py` — the central, always-run report. Reads raw
    `events.jsonl` directly (single-cow today) or merged per-site digests
    (`--herd`, once the herd lands).
  * the cow-side digest emitter (herd step-1) — runs the SAME classifier
    at the edge so each drone ships a compact `digest.jsonl` instead of
    its full raw log.

Keeping parse+classify here guarantees both ends agree on what a
`cve-2026-5946-trigger` (etc.) is: one classifier, two call sites. Nothing
in this module prints or renders — that stays in `morning_report.py`.
"""

from __future__ import annotations

import collections
import ipaddress
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

# ---- classifiers -----------------------------------------------------------

# Well-known server-fingerprint qnames probed in the CHAOS class (and the
# occasional HESIOD variant). Querying these is the *legitimate* non-IN-class
# use against us — banner recon, the oldest DNS fingerprinting trick there is.
# Recognize them generously (RD bit and qtype be damned) so a plain
# `version.bind` probe doesn't get promoted into the CVE bucket just because a
# sloppy scanner left RD=1 on or asked with qtype A.
BIND_CHAOS = {
    "version.bind.",
    "hostname.bind.",
    "id.server.",
    "authors.bind.",
    "version.server.",
    "hostname.server.",
    "id.bind.",
}

# Canary qnames used by open-resolver scanners to detect whether a host
# will answer recursively for names it isn't authoritative for. These
# are names that *should* resolve in the wild; receiving a useful answer
# from a non-Google nameserver tells the scanner the target is an open
# resolver. `dnsscan.shadowserver.org` was the classic canary, but it's
# now exempted by most honeypots and well-behaved auth servers, so
# scanners have started rotating to high-recognition names. First member
# observed: `google.com.` (256-query cluster on 2026-05-20/21 from
# AS60223 NETIFACE + AS205759 GHOSTYNETWORKS). Grow this set as new
# canary names appear; keep entries narrow (exact lowercased FQDN match
# with trailing dot) since "saw google.com.A from somewhere" is the
# *only* signal — we don't want to false-positive on, say, a chaos-class
# fingerprinter that happens to also touch cloudflare.com.
OPEN_RESOLVER_CANARIES = {
    "google.com.",
}


def is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def ip_version(ip: str) -> int | None:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def is_our_ip(ip: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def load_our_ips(path: Path | None, extra: list[str]) -> list[ipaddress._BaseNetwork]:
    """Load a list of IPs/CIDRs identifying our own infrastructure.

    Entries from `path` (one IP/CIDR per line, # comments allowed) are
    combined with any `--our-ip` overrides. Bare IPs become /32 or /128.
    """
    nets: list[ipaddress._BaseNetwork] = []
    raw: list[str] = []
    if path is not None:
        try:
            for line in path.read_text().splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    raw.append(line)
        except OSError as exc:
            print(f"[our-ips] cannot read {path}: {exc}", file=sys.stderr)
    raw.extend(extra)
    for entry in raw:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            print(f"[our-ips] skipping {entry!r}: {exc}", file=sys.stderr)
    return nets


def load_research_cidrs(path: Path | None) -> list[ipaddress._BaseNetwork]:
    """Load known-research scanner CIDRs (one per line, # comments) so the
    report can tell research probes apart from un-attributed traffic.

    Same format as `config/source_exemptions.txt`. Returns [] if path is
    None or unreadable; the report still works, just without the split.
    """
    if path is None:
        return []
    nets: list[ipaddress._BaseNetwork] = []
    try:
        text = path.read_text()
    except OSError as exc:
        print(f"[research-cidrs] cannot read {path}: {exc}", file=sys.stderr)
        return nets
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            print(f"[research-cidrs] skipping {entry!r}: {exc}", file=sys.stderr)
    return nets


def ip_in_nets(ip: str, nets: list[ipaddress._BaseNetwork]) -> bool:
    if not nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


FLAG_RD = 0x0100  # DNS header RD bit


def classify_query(event: dict) -> str:
    qname = event.get("qname", "")
    qclass = event.get("qclass_name", "IN")
    opcode = event.get("opcode", "QUERY")

    if not qname:
        return "empty"
    low = qname.lower()
    banner_qname = low in BIND_CHAOS

    # Non-IN classes (CHAOS, HESIOD) have one legitimate use against us:
    # banner-fingerprint probes for a known server-info qname (`version.bind`,
    # `id.server`, ...). Treat those as `chaos-banner` regardless of the RD bit
    # or qtype — RD=1 on a CHAOS query is sloppy-but-ubiquitous scanner default,
    # not exploit intent, and `CH/A version.bind.` is still plainly recon.
    #
    # Reserve `cve-2026-5946-trigger` for what the CVE is actually about: a
    # non-IN-class query whose qname is NOT a known banner name (e.g.
    # `CH/A honeycow.net.`, `HS/A a.`, `CH/TXT www.stage.`), or a non-IN query
    # with a non-QUERY opcode — the shapes that exercise BIND's non-IN-class
    # code path rather than its banner-response path.
    if qclass in {"CH", "HS"}:
        if banner_qname and opcode == "QUERY":
            return "chaos-banner"
        return "cve-2026-5946-trigger"

    # IN-class banner-qname queries (`TXT version.bind` in class IN —
    # scanners that don't bother setting the chaos class). Same category
    # for reporting purposes; the CVE bucket above is class-gated.
    if banner_qname:
        return "chaos-banner"
    if "asertdnsresearch" in low:
        return "asert-netscout"
    if "shadowserver" in low:
        return "shadowserver"
    if low.endswith(".cybergreen.net.") or low.endswith(".cyberresilience.io."):
        return "open-resolver-test"
    if low in OPEN_RESOLVER_CANARIES:
        return "open-resolver-canary"
    if qname != low and any(c.isupper() for c in qname):
        return "0x20-case-mix"
    return "other"


# Maps known scanner-research zones (suffix match on lowercased qname) to a
# short org label. Kept in sync with config/exemptions.txt's research-scanner block.
RESEARCH_SCANNER_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".shadowserver.org.", "shadowserver"),
    (".cybergreen.net.", "cybergreen"),
    (".cyberresilience.io.", "cyber-resilience"),
    (".internet-measurement.com.", "driftnet/p25499"),
    (".internet-census.org.", "internet-census"),
    (".asertdnsresearch.com.", "asert-netscout"),
    (".asertdnsresearch.net.", "asert-netscout"),
)


def classify_research_scanner(qname: str) -> str | None:
    if not qname:
        return None
    low = qname.lower()
    for suffix, label in RESEARCH_SCANNER_SUFFIXES:
        if low == suffix.lstrip(".") or low.endswith(suffix):
            return label
    return None


# ---- UFW log parser --------------------------------------------------------

UFW_RE = re.compile(
    r"\[UFW (?P<verdict>[A-Z ]+)\].*?"
    r"SRC=(?P<src>\S+).*?"
    r"DST=(?P<dst>\S+).*?"
    r"PROTO=(?P<proto>\S+)"
    r"(?:.*?DPT=(?P<dpt>\d+))?",
)


def parse_ufw(path: Path, since: datetime) -> list[dict]:
    """Yield UFW log lines newer than `since` as dicts."""
    out = []
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        print(f"[ufw] cannot read {path}: {exc}", file=sys.stderr)
        return out
    for line in text.splitlines():
        # Lines start with an ISO-ish timestamp, e.g.
        # "2026-05-19T12:47:28.879641-05:00 host kernel: [UFW BLOCK] ..."
        ts_str, _, rest = line.partition(" ")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        if ts < since:
            continue
        m = UFW_RE.search(rest)
        if not m:
            continue
        d = m.groupdict()
        d["ts"] = ts
        d["verdict"] = d["verdict"].strip()
        out.append(d)
    return out


# ---- event loader ----------------------------------------------------------

def load_events(path: Path, since: datetime) -> list[dict]:
    events = []
    with path.open() as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            try:
                ts = datetime.fromisoformat(e["ts"])
            except (KeyError, ValueError):
                continue
            if ts < since:
                continue
            e["_ts"] = ts
            events.append(e)
    return events


def bucket_v4_v6(ips: collections.Counter) -> tuple[int, int, int]:
    v4 = v6 = unknown = 0
    for ip, n in ips.items():
        v = ip_version(ip)
        if v == 4:
            v4 += n
        elif v == 6:
            v6 += n
        else:
            unknown += n
    return v4, v6, unknown
