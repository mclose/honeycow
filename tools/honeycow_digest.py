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

import argparse
import collections
import ipaddress
import json
import re
import sys
from datetime import UTC, datetime, timedelta
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


# HTTP-side twin of classify_query: maps a request path to a short probe-family
# label. Two match strategies, checked most-specific first:
#   * HTTP_PROBE_SIGNATURES — exact match on the bare path (query string /
#     fragment stripped, case-insensitive). For endpoints whose *path* is the
#     whole tell.
#   * HTTP_PROBE_SUBSTRINGS — substring match on the full lowercased target
#     (query string INCLUDED). For campaigns whose signature rides in the
#     query string (php-cgi arg injection) or varies the path around a stable
#     token (phpunit vendor depth, apache traversal depth).
# Either way the label is derivable from the `http_paths` counts every digest
# already carries — those keys are the full raw request target (honey_http.py
# logs method + full request-URI) — so no digest schema bump is needed to start
# reporting families. Add signatures here as new campaigns show up.
HTTP_PROBE_SIGNATURES: tuple[tuple[str, str], ...] = (
    # CVE-2021-36260 — unauthenticated command injection in Hikvision IP
    # camera / NVR firmware (CVSS 9.8). The RCE itself is a PUT carrying an
    # XML `<language>$(cmd)</language>` body; the GET /SDK/webLanguage we see
    # is the recon leg that fingerprints the endpoint before the payload.
    ("/sdk/weblanguage", "hikvision-webLanguage"),
    # Exposed VCS metadata — source/secret disclosure.
    ("/.git/config", "git-config-leak"),
)

# Substring signatures matched against the full lowercased target (path AND
# query string). Ordered most-specific first; first hit wins.
HTTP_PROBE_SUBSTRINGS: tuple[tuple[str, str], ...] = (
    # CVE-2012-1823 — php-cgi argument injection. The attacker's `-d` flags
    # ride in the query string (`...auto_prepend_file=php://input`, URL-encoded
    # on the wire as `%ADd` / `%3d`), so we match the payload token rather than
    # the (arbitrary, often `/` or `/hello.world`) path.
    ("auto_prepend_file", "php-cgi-rce"),
    # CVE-2017-9841 — PHPUnit eval-stdin.php RCE. Scanners spray many vendor
    # path depths; the trailing script name is the stable tell.
    ("eval-stdin.php", "phpunit-rce"),
    # CVE-2021-41773 / -42013 — Apache path traversal to RCE via encoded
    # dot-segments under cgi-bin (`/cgi-bin/.%2e/.../bin/sh`).
    ("/cgi-bin/.%2e", "apache-traversal"),
)


def classify_http(path: str) -> str:
    if not path:
        return "empty"
    full = path.lower()
    bare = full.split("?", 1)[0].split("#", 1)[0]
    for needle, label in HTTP_PROBE_SIGNATURES:
        if bare == needle:
            return label
    # dotenv harvesting: `/.env` plus the `.env.local` / `.env.production`
    # / `.env.backup` / … family that scanners spray as a set.
    if bare == "/.env" or bare.startswith("/.env."):
        return "env-harvest"
    for needle, label in HTTP_PROBE_SUBSTRINGS:
        if needle in full:
            return label
    return "other"


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


# ---- digest emitter (cow-side edge map step) -------------------------------
#
# Each cow runs the classifier above at the edge and ships a compact per-hour
# digest line instead of its full raw events.jsonl. The central report merges
# digests (`morning_report --herd`) so report time is flat vs herd size and
# never blocks on a slow/dead cow — Matthew's hard constraint. The full raw
# log stays on the cow (capture-wide, redact-at-publish).
#
# Schema is deliberately O(unique keys/hour), not O(events): per-IP rollups
# in `by_src`, Counters for paths/UAs/ports/families, and a small bounded set
# of raw `exemplars` for the shapes that are worth the bytes (CVE triggers,
# oversized inbound QR=1). One JSON object per line per hour bucket.

DIGEST_SCHEMA = "honeycow-digest-v1"

# Caps so a single noisy hour can't blow up a digest line. Exemplars are the
# only place we keep whole raw events; everything else is aggregate counts.
MAX_CVE_EXEMPLARS = 50
MAX_QR_EXEMPLARS = 50
MAX_QNAMES_PER_ORG = 10

# Slim projection of a raw event kept as an exemplar — enough to eyeball the
# probe shape without shipping the whole record.
_EXEMPLAR_FIELDS = (
    "ts", "src_ip", "src_port", "qname", "qtype_name", "qclass_name",
    "opcode", "flags", "drop_reason", "response_kind", "response_bytes",
)


def _exemplar(event: dict) -> dict:
    return {k: event[k] for k in _EXEMPLAR_FIELDS if k in event}


def summarize_window(
    events: list[dict],
    ufw: list[dict],
    *,
    site_id: str,
    hour_iso: str,
    research_nets: list[ipaddress._BaseNetwork] | None = None,
) -> dict:
    """Aggregate one window of events + UFW lines into a single digest dict.

    `events`/`ufw` are assumed pre-filtered to the window (e.g. one hour).
    The result is JSON-serialisable and is the unit the collector merges.

    Selftest/external splitting is intentionally NOT done here — a throwaway
    cow may not know the operator's own-IP list. by_src keeps raw per-IP
    counts so the central report can apply `--our-ips` at merge time. Family
    and scanner rollups are computed over all non-internal queries (== the
    report's `ext` when no --our-ips is given, which is the flagship default).
    """
    research_nets = research_nets or []

    queries = [e for e in events if e.get("event") == "query"]
    drops = [e for e in events if e.get("event") == "query_drop"]
    http = [e for e in events if e.get("event") == "http_closer"]
    ext = [e for e in queries if not is_private_or_loopback(e.get("src_ip", ""))]

    # --- per-IP rollup (the backbone; report re-derives top-sources,
    # correlation, v4/v6 splits, source-exempt counts from this) ---
    by_src: dict[str, dict] = {}

    def _slot(ip: str) -> dict:
        s = by_src.get(ip)
        if s is None:
            s = {
                "dns": 0, "http": 0, "ufw": 0,
                "qtypes": collections.Counter(),
                "qclasses": collections.Counter(),
                "families": collections.Counter(),
                "handlers": collections.Counter(),
                "ufw_ports": collections.Counter(),
                "first": None, "last": None,
            }
            by_src[ip] = s
        return s

    def _stamp(slot: dict, ts: str | None) -> None:
        if not ts:
            return
        if slot["first"] is None or ts < slot["first"]:
            slot["first"] = ts
        if slot["last"] is None or ts > slot["last"]:
            slot["last"] = ts

    families: collections.Counter = collections.Counter()
    for e in ext:
        ip = e.get("src_ip", "")
        slot = _slot(ip)
        slot["dns"] += 1
        slot["qtypes"][e.get("qtype_name", "?")] += 1
        slot["qclasses"][e.get("qclass_name", "?")] += 1
        fam = classify_query(e)
        slot["families"][fam] += 1
        families[fam] += 1
        if e.get("handler"):
            slot["handlers"][e["handler"]] += 1
        _stamp(slot, e.get("ts"))

    for e in http:
        ip = e.get("client_ip") or e.get("src_ip") or ""
        slot = _slot(ip)
        slot["http"] += 1
        _stamp(slot, e.get("ts"))

    for u in ufw:
        ip = u.get("src", "")
        slot = _slot(ip)
        slot["ufw"] += 1
        if u.get("dpt"):
            slot["ufw_ports"][f"{u.get('proto', '?').lower()}/{u['dpt']}"] += 1

    # --- top-level Counters the report shows directly ---
    http_paths: collections.Counter = collections.Counter(
        e.get("path") for e in http
    )
    http_user_agents: collections.Counter = collections.Counter(
        e.get("user_agent") for e in http
    )
    ufw_ports: collections.Counter = collections.Counter(
        f"{u.get('proto', '?').lower()}/{u['dpt']}" for u in ufw if u.get("dpt")
    )
    source_exempt: collections.Counter = collections.Counter(
        e.get("src_ip", "") for e in ext if e.get("handler") == "exempt_source"
    )

    # --- research scanners (REFUSED via exemptions, still observed) ---
    research: dict[str, dict] = {}
    for e in ext:
        label = classify_research_scanner(e.get("qname", ""))
        if label is None:
            continue
        org = research.setdefault(
            label,
            {"hits": 0, "refused": 0,
             "src_ips": collections.Counter(), "qnames": set()},
        )
        org["hits"] += 1
        if e.get("response_kind") == "REFUSED":
            org["refused"] += 1
        org["src_ips"][e.get("src_ip", "")] += 1
        if len(org["qnames"]) < MAX_QNAMES_PER_ORG:
            org["qnames"].add(e.get("qname", ""))

    # --- unsolicited inbound QR=1 (scanner probe / reflection-victim) ---
    inbound_qr = [
        e for e in drops
        if e.get("src_port") == 53
        and e.get("drop_reason") in ("DROPPED_QR", "oversized_datagram")
    ]
    qr_research = [e for e in inbound_qr if ip_in_nets(e["src_ip"], research_nets)]
    qr_oversized = [
        e for e in inbound_qr if e.get("drop_reason") == "oversized_datagram"
    ]
    inbound = {
        "total": len(inbound_qr),
        "research": len(qr_research),
        "unknown": len(inbound_qr) - len(qr_research),
        "oversized_total": len(qr_oversized),
        "oversized_unknown": sum(
            1 for e in qr_oversized if not ip_in_nets(e["src_ip"], research_nets)
        ),
        "by_ip": dict(collections.Counter(e["src_ip"] for e in inbound_qr)),
        "oversized_by_ip": dict(
            collections.Counter(e["src_ip"] for e in qr_oversized)
        ),
    }

    # --- exemplars: the only raw events we keep, bounded ---
    cve_exemplars = [
        _exemplar(e) for e in ext
        if classify_query(e) == "cve-2026-5946-trigger"
    ][:MAX_CVE_EXEMPLARS]
    qr_exemplars = [_exemplar(e) for e in qr_oversized][:MAX_QR_EXEMPLARS]

    def _jsonable_src(slot: dict) -> dict:
        return {
            "dns": slot["dns"], "http": slot["http"], "ufw": slot["ufw"],
            "qtypes": dict(slot["qtypes"]),
            "qclasses": dict(slot["qclasses"]),
            "families": dict(slot["families"]),
            "handlers": dict(slot["handlers"]),
            "ufw_ports": dict(slot["ufw_ports"]),
            "first": slot["first"], "last": slot["last"],
        }

    return {
        "schema": DIGEST_SCHEMA,
        "site_id": site_id,
        "hour": hour_iso,
        "totals": {
            "events": len(events),
            "dns_queries": len(queries),
            "dns_external": len(ext),
            "dns_drops": len(drops),
            "http": len(http),
            "ufw": len(ufw),
        },
        "families": dict(families),
        "http_paths": dict(http_paths),
        "http_user_agents": dict(http_user_agents),
        "ufw_ports": dict(ufw_ports),
        "source_exempt": dict(source_exempt),
        "research_scanners": {
            org: {
                "hits": d["hits"], "refused": d["refused"],
                "src_ips": dict(d["src_ips"]),
                "qnames": sorted(d["qnames"]),
            }
            for org, d in research.items()
        },
        "inbound_qr": inbound,
        "cve_exemplars": cve_exemplars,
        "qr_exemplars": qr_exemplars,
        "by_src": {ip: _jsonable_src(s) for ip, s in by_src.items()},
    }


def _hour_floor(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def iter_hourly_digests(
    events: list[dict],
    ufw: list[dict],
    *,
    site_id: str,
    research_nets: list[ipaddress._BaseNetwork] | None = None,
) -> list[dict]:
    """Bucket events + UFW lines by UTC hour and summarise each bucket.

    Events carry `_ts` (added by `load_events`); UFW dicts carry `ts` (added
    by `parse_ufw`). Returns one digest dict per hour, oldest first.
    """
    ev_by_hour: dict[datetime, list[dict]] = collections.defaultdict(list)
    for e in events:
        ts = e.get("_ts")
        if ts is None:
            continue
        ev_by_hour[_hour_floor(ts.astimezone(UTC))].append(e)

    ufw_by_hour: dict[datetime, list[dict]] = collections.defaultdict(list)
    for u in ufw:
        ts = u.get("ts")
        if ts is None:
            continue
        ufw_by_hour[_hour_floor(ts.astimezone(UTC))].append(u)

    hours = sorted(set(ev_by_hour) | set(ufw_by_hour))
    return [
        summarize_window(
            ev_by_hour.get(h, []),
            ufw_by_hour.get(h, []),
            site_id=site_id,
            hour_iso=h.isoformat(),
            research_nets=research_nets,
        )
        for h in hours
    ]


# ---- digest merge (collector / report side) --------------------------------
#
# The central report reads many per-site digest.jsonl files and merges them
# back into one aggregate with the same shape as a single digest (Counters
# summed, by_src unioned). Report time is O(total unique keys), independent
# of raw event volume — and a missing/slow cow just contributes nothing.


def load_digests(paths: list[Path]) -> list[dict]:
    """Load digest dicts from a list of files and/or directories.

    Directories are scanned for `*.jsonl`. Lines that aren't valid JSON or
    aren't our schema are skipped (a half-written tail line from an
    in-flight rsync must never crash the report). Returns dicts in file
    order; merge order doesn't matter.
    """
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.glob("*.jsonl")))
        else:
            files.append(p)
    out: list[dict] = []
    for f in files:
        try:
            text = f.read_text()
        except OSError as exc:
            print(f"[digests] cannot read {f}: {exc}", file=sys.stderr)
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if d.get("schema") == DIGEST_SCHEMA:
                out.append(d)
    return out


def _merge_counter(dst: collections.Counter, src: dict | None) -> None:
    if src:
        dst.update(src)


def merge_digests(digests: list[dict]) -> dict:
    """Merge per-site/per-hour digests into one aggregate.

    Same shape as a single digest's body plus herd provenance: `sites`
    (per-site hour counts) and a `fan_out` map (src_ip -> set of sites it
    was seen at) — the cross-vantage metric a single cow can't produce.
    by_src `sites` records which vantage points saw each IP.
    """
    totals: collections.Counter = collections.Counter()
    families: collections.Counter = collections.Counter()
    http_paths: collections.Counter = collections.Counter()
    http_user_agents: collections.Counter = collections.Counter()
    ufw_ports: collections.Counter = collections.Counter()
    source_exempt: collections.Counter = collections.Counter()
    research: dict[str, dict] = {}
    inbound = {
        "total": 0, "research": 0, "unknown": 0,
        "oversized_total": 0, "oversized_unknown": 0,
        "by_ip": collections.Counter(), "oversized_by_ip": collections.Counter(),
    }
    cve_exemplars: list[dict] = []
    qr_exemplars: list[dict] = []
    by_src: dict[str, dict] = {}
    sites: dict[str, int] = collections.Counter()

    def _src_slot(ip: str) -> dict:
        s = by_src.get(ip)
        if s is None:
            s = {
                "dns": 0, "http": 0, "ufw": 0,
                "qtypes": collections.Counter(),
                "qclasses": collections.Counter(),
                "families": collections.Counter(),
                "handlers": collections.Counter(),
                "ufw_ports": collections.Counter(),
                "first": None, "last": None, "sites": set(),
            }
            by_src[ip] = s
        return s

    for d in digests:
        site = d.get("site_id", "") or "(unset)"
        sites[site] += 1
        _merge_counter(totals, d.get("totals"))
        _merge_counter(families, d.get("families"))
        _merge_counter(http_paths, d.get("http_paths"))
        _merge_counter(http_user_agents, d.get("http_user_agents"))
        _merge_counter(ufw_ports, d.get("ufw_ports"))
        _merge_counter(source_exempt, d.get("source_exempt"))

        for org, od in (d.get("research_scanners") or {}).items():
            tgt = research.setdefault(
                org, {"hits": 0, "refused": 0,
                      "src_ips": collections.Counter(), "qnames": set()},
            )
            tgt["hits"] += od.get("hits", 0)
            tgt["refused"] += od.get("refused", 0)
            _merge_counter(tgt["src_ips"], od.get("src_ips"))
            tgt["qnames"].update(od.get("qnames") or [])

        iq = d.get("inbound_qr") or {}
        for k in ("total", "research", "unknown",
                  "oversized_total", "oversized_unknown"):
            inbound[k] += iq.get(k, 0)
        _merge_counter(inbound["by_ip"], iq.get("by_ip"))
        _merge_counter(inbound["oversized_by_ip"], iq.get("oversized_by_ip"))

        cve_exemplars.extend(d.get("cve_exemplars") or [])
        qr_exemplars.extend(d.get("qr_exemplars") or [])

        for ip, s in (d.get("by_src") or {}).items():
            slot = _src_slot(ip)
            slot["dns"] += s.get("dns", 0)
            slot["http"] += s.get("http", 0)
            slot["ufw"] += s.get("ufw", 0)
            _merge_counter(slot["qtypes"], s.get("qtypes"))
            _merge_counter(slot["qclasses"], s.get("qclasses"))
            _merge_counter(slot["families"], s.get("families"))
            _merge_counter(slot["handlers"], s.get("handlers"))
            _merge_counter(slot["ufw_ports"], s.get("ufw_ports"))
            slot["sites"].add(site)
            f, last = s.get("first"), s.get("last")
            if f and (slot["first"] is None or f < slot["first"]):
                slot["first"] = f
            if last and (slot["last"] is None or last > slot["last"]):
                slot["last"] = last

    return {
        "sites": dict(sites),
        "totals": totals,
        "families": families,
        "http_paths": http_paths,
        "http_user_agents": http_user_agents,
        "ufw_ports": ufw_ports,
        "source_exempt": source_exempt,
        "research_scanners": research,
        "inbound_qr": inbound,
        "cve_exemplars": cve_exemplars,
        "qr_exemplars": qr_exemplars,
        "by_src": by_src,
    }


# ---- CLI -------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Emit compact per-hour HoneyCow digest lines from raw logs.",
    )
    ap.add_argument("--events", required=True, type=Path,
                    help="path to events.jsonl")
    ap.add_argument("--ufw", type=Path, default=None,
                    help="optional path to /var/log/ufw.log")
    ap.add_argument("--out", type=Path, default=None,
                    help="append digest lines here (default: stdout)")
    ap.add_argument("--site-id", default=None,
                    help="vantage-point id to stamp (default: $HONEY_SITE_ID)")
    ap.add_argument("--hours", type=float, default=None,
                    help="only summarise the last N hours (default: all)")
    ap.add_argument("--research-cidrs-file", type=Path,
                    default=Path("config/source_exemptions.txt"),
                    help="known-research scanner CIDRs for inbound-QR split")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be written without touching --out")
    args = ap.parse_args(argv)

    import os
    site_id = args.site_id if args.site_id is not None else os.environ.get(
        "HONEY_SITE_ID", "",
    ).strip()

    since = datetime.min.replace(tzinfo=UTC)
    if args.hours is not None:
        since = datetime.now(tz=UTC) - timedelta(hours=args.hours)

    research_nets = load_research_cidrs(
        args.research_cidrs_file if args.research_cidrs_file.exists() else None,
    )
    events = load_events(args.events, since)
    ufw = parse_ufw(args.ufw, since) if args.ufw else []
    digests = iter_hourly_digests(
        events, ufw, site_id=site_id, research_nets=research_nets,
    )
    lines = [json.dumps(d, ensure_ascii=False) for d in digests]

    if args.dry_run:
        dest = f"append to {args.out}" if args.out else "stdout"
        print(
            f"[dry-run] would emit {len(lines)} hourly digest line(s) "
            f"(site_id={site_id!r}) -> {dest}",
            file=sys.stderr,
        )
        for line in lines:
            print(line)
        return 0

    if args.out:
        with args.out.open("a", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        print(f"wrote {len(lines)} digest line(s) to {args.out}", file=sys.stderr)
    else:
        for line in lines:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
