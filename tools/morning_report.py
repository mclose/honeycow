#!/usr/bin/env python3
"""Generate a morning summary of HoneyCow activity.

Reads HoneyCow's JSONL event log plus optionally `/var/log/ufw.log`,
buckets by source IP family (v4 vs v6), classifies scanner traffic by
well-known fingerprint families, and surfaces correlations between
kernel-level port probes and application-level requests.

Run on the host or pull the files locally first:

    scp <vps>:/var/lib/docker/volumes/honeycow_honeycow_logs/_data/events.jsonl .
    scp <vps>:/var/log/ufw.log .
    tools/morning_report.py --events events.jsonl --ufw ufw.log \\
        --hours 24 --cert-issued 2026-05-20 \\
        --our-ips-file tools/our-ips.txt

`--cert-issued` (optional) marks a CT-log expected spike date — the
report compares external DNS query counts before vs after that
timestamp so a fresh-cert ramp is easy to spot.

`--our-ips-file` (optional) loads a list of operator-owned IPs/CIDRs
(gitignored; see `tools/our-ips.txt.example`). Matching sources are
bucketed as self-test and excluded from external-traffic views so
triage focuses on "not us" probes. `--our-ip IP/CIDR` (repeatable)
adds extras inline.
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


# ---- event analysis --------------------------------------------------------

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


def section(title: str) -> None:
    print(f"\n=== {title} ===")


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


def render(
    events: list[dict],
    ufw: list[dict],
    cert_issued: datetime | None,
    our_nets: list[ipaddress._BaseNetwork] | None = None,
    research_nets: list[ipaddress._BaseNetwork] | None = None,
) -> None:
    our_nets = our_nets or []
    research_nets = research_nets or []
    queries = [e for e in events if e.get("event") == "query"]
    # "external" = not private/loopback. Self-test = external AND in our_nets.
    # We split them so triage focuses on "not us" traffic, while keeping
    # self-test visible (its mere presence is signal — outbound infra
    # querying its own bluff host is worth noticing).
    non_internal = [e for e in queries if not is_private_or_loopback(e.get("src_ip", ""))]
    selftest = [e for e in non_internal if is_our_ip(e.get("src_ip", ""), our_nets)]
    ext = [e for e in non_internal if not is_our_ip(e.get("src_ip", ""), our_nets)]
    drops = [e for e in events if e.get("event") == "query_drop"]
    http = [e for e in events if e.get("event") == "http_closer"]

    section("totals")
    print(f"  events:        {len(events)}")
    if our_nets:
        print(
            f"  DNS queries:   {len(queries)} "
            f"(external: {len(ext)}, self-test: {len(selftest)})"
        )
    else:
        print(f"  DNS queries:   {len(queries)} (external: {len(ext)})")
    print(f"  DNS drops:     {len(drops)}")
    print(f"  HTTP closer:   {len(http)}")
    print(f"  UFW log lines: {len(ufw)}")

    # --- v4/v6 split ---
    section("IPv4 vs IPv6")
    ext_ips = collections.Counter(e["src_ip"] for e in ext)
    selftest_ips = collections.Counter(e["src_ip"] for e in selftest)
    v4, v6, unk = bucket_v4_v6(ext_ips)
    print(f"  external DNS queries — v4: {v4}  v6: {v6}  other: {unk}")
    if our_nets:
        v4s, v6s, unks = bucket_v4_v6(selftest_ips)
        print(f"  self-test DNS queries — v4: {v4s}  v6: {v6s}  other: {unks}")
    http_ips = collections.Counter(
        e.get("client_ip") or e.get("src_ip") for e in http
        if not is_private_or_loopback(e.get("client_ip") or "")
        or e.get("client_ip") == e.get("src_ip")
    )
    v4h, v6h, unkh = bucket_v4_v6(http_ips)
    print(f"  HTTP closer (client_ip) — v4: {v4h}  v6: {v6h}  other: {unkh}")
    ufw_ips = collections.Counter(u["src"] for u in ufw)
    v4u, v6u, unku = bucket_v4_v6(ufw_ips)
    print(f"  UFW blocked  — v4: {v4u}  v6: {v6u}  other: {unku}")
    # Sanity check: v6's share of reached DNS should roughly track its share
    # of UFW traffic. If reached-share collapses to ~0 while UFW-share is
    # nonzero, v6 ingress is broken (the pre-2026-05-20 bug). Both shares
    # nonzero and similar = v6 ingress healthy.
    reached_total = v4 + v6
    ufw_total = v4u + v6u
    if reached_total and ufw_total:
        reached_v6_pct = 100 * v6 / reached_total
        ufw_v6_pct = 100 * v6u / ufw_total
        print(
            f"  v6 ingress check — v6 share of reached DNS: {reached_v6_pct:.1f}%  "
            f"v6 share of UFW: {ufw_v6_pct:.1f}%"
        )

    # --- self-test traffic (our own infra showing up in the logs) ---
    # Not a threat — but worth surfacing because it's worth knowing when
    # *our* boxes are talking to the bluff (intentional dig sessions,
    # outbound recursive lookups from our own resolvers landing back here
    # via delegation, etc.). Excluded from `ext` everywhere downstream so
    # top-sources / scanner families / CT-spike views show "not us" only.
    if our_nets:
        section("self-test traffic (our infra in the logs)")
        if not selftest:
            print("  (none in window)")
        else:
            qnames = collections.Counter(e.get("qname", "") for e in selftest)
            print(f"  total queries: {len(selftest)} from {len(selftest_ips)} our IPs")
            for ip, n in selftest_ips.most_common():
                print(f"    {n:4d}  {ip}  (v{ip_version(ip)})")
            print("  top qnames:")
            for q, n in qnames.most_common(5):
                preview = q if len(q) <= 70 else q[:67] + "..."
                print(f"    {n:4d}  {preview}")

    # --- unsolicited DNS responses arriving at :53 ---
    # query_drop events with src_port=53 and DROPPED_QR / oversized_datagram
    # are inbound packets with the QR (response) bit set — i.e. responses
    # to queries we never issued. Two distinct shapes share this signature:
    #
    #   1. Research-scanner probes (Shadowserver et al.) sending us crafted
    #      "responses" to test whether we accept stray packets on :53 — an
    #      open-resolver / cache-poisonability check. Source IP sits in a
    #      known-research CIDR.
    #   2. Genuine reflection attempts where an attacker spoofed our IP as
    #      the victim, queried some auth NS, and that NS sent its real
    #      response to us. Source IP is some unwitting auth NS.
    #
    # We can't tell them apart from packet content alone, but the source
    # CIDR is a strong tell. Either way honeycow correctly drops them via
    # the qr_set handler. The high-signal sub-bucket is `oversized_datagram`
    # without a research CIDR — that's the shape most consistent with a
    # real reflection-amplification map.
    section("unsolicited DNS responses arriving at :53 "
            "(QR=1 inbound — scanner probes and/or reflection-victim)")
    inbound_qr = [
        e for e in drops
        if e.get("src_port") == 53
        and e.get("drop_reason") in ("DROPPED_QR", "oversized_datagram")
    ]
    if not inbound_qr:
        print("  (none in window)")
    else:
        research = [e for e in inbound_qr if ip_in_nets(e["src_ip"], research_nets)]
        unknown = [e for e in inbound_qr if not ip_in_nets(e["src_ip"], research_nets)]
        oversized_all = [
            e for e in inbound_qr if e.get("drop_reason") == "oversized_datagram"
        ]
        print(f"  total inbound QR=1 packets: {len(inbound_qr)} "
              f"(research-CIDR: {len(research)}  unknown: {len(unknown)})")
        if oversized_all:
            oversized_unknown = [
                e for e in oversized_all
                if not ip_in_nets(e["src_ip"], research_nets)
            ]
            print(f"  oversized (>512B): {len(oversized_all)} total, "
                  f"{len(oversized_unknown)} from non-research sources "
                  f"(higher reflection-attempt signal)")
        if research:
            print("  research-scanner probes (cache-poisoning / open-resolver test):")
            by_ip = collections.Counter(e["src_ip"] for e in research)
            for ip, n in by_ip.most_common(10):
                print(f"    {n:4d}  {ip}")
        if unknown:
            print("  unknown sources (possible reflection victim or untagged scanner):")
            by_ip = collections.Counter(e["src_ip"] for e in unknown)
            oversized_by_ip = collections.Counter(
                e["src_ip"] for e in unknown
                if e.get("drop_reason") == "oversized_datagram"
            )
            for ip, n in by_ip.most_common(10):
                osz = f"  ({oversized_by_ip[ip]} oversized)" if oversized_by_ip[ip] else ""
                print(f"    {n:4d}  {ip}{osz}")

    # --- source-IP exemption hits (Layer 1 defense visibility) ---
    section("source-IP exemption hits (REFUSED by source CIDR)")
    src_exempt = [e for e in ext if e.get("handler") == "exempt_source"]
    if not src_exempt:
        print("  (none in window)")
    else:
        by_ip = collections.Counter(e["src_ip"] for e in src_exempt)
        print(f"  total: {len(src_exempt)} queries from {len(by_ip)} unique IPs")
        for ip, n in by_ip.most_common(10):
            print(f"    {n:4d}  {ip}")

    # --- scanner fingerprint families ---
    section("DNS probe families")
    fam_labels = [(e, classify_query(e)) for e in ext]
    fam = collections.Counter(label for _, label in fam_labels)
    for k, n in fam.most_common():
        print(f"  {n:4d}  {k}")

    # --- CVE-2026-5946 trigger candidates (BIND non-IN-class DoS) ---
    # See https://kb.isc.org/docs/cve-2026-5946 — non-IN-class queries
    # used in IN-only contexts trigger assertion failures in named.
    # We're not vulnerable; this section surfaces the recon shape so
    # campaigns are visible early.
    cve_hits = [e for e, label in fam_labels if label == "cve-2026-5946-trigger"]
    if cve_hits:
        section("CVE-2026-5946 trigger candidates")
        by_ip = collections.Counter(e["src_ip"] for e in cve_hits)
        print(f"  total: {len(cve_hits)} queries from {len(by_ip)} unique IPs")
        for ip, n in by_ip.most_common(10):
            samples = [e for e in cve_hits if e["src_ip"] == ip][:3]
            print(f"    {n:3d}x {ip}")
            for e in samples:
                rd = "RD=1" if e.get("flags", 0) & FLAG_RD else "RD=0"
                print(
                    f"        {e.get('qclass_name','?')}/{e.get('qtype_name','?'):<6} "
                    f"{e.get('opcode','?'):<6} {rd}  {e.get('qname','')!r}"
                )

    # --- research scanners: acknowledged + REFUSED via exemptions.txt ---
    # We want these visible, not hidden, even though we REFUSE them at the
    # wire. Honeycow is the passive listener; these orgs are the active
    # scanners — both halves of the picture matter.
    section("research scanners (REFUSED via exemptions, still observed)")
    research = [
        e for e in ext
        if classify_research_scanner(e.get("qname", "")) is not None
    ]
    if not research:
        print("  (none in window)")
    else:
        by_org: dict[str, list[dict]] = collections.defaultdict(list)
        for e in research:
            label = classify_research_scanner(e["qname"]) or "unknown"
            by_org[label].append(e)
        for org in sorted(by_org, key=lambda k: -len(by_org[k])):
            org_events = by_org[org]
            ips = collections.Counter(e["src_ip"] for e in org_events)
            qnames = sorted({e.get("qname", "") for e in org_events})
            refused = sum(
                1 for e in org_events if e.get("response_kind") == "REFUSED"
            )
            print(
                f"  {org:18s}  hits={len(org_events):3d}  refused={refused:3d}  "
                f"src_ips={len(ips)}",
            )
            for ip, n in ips.most_common(5):
                print(f"      {n:3d}x {ip}")
            for q in qnames[:3]:
                print(f"      qname: {q}")

    # --- top sources ---
    section("top external DNS sources (10)")
    for ip, n in ext_ips.most_common(10):
        print(f"  {n:4d}  {ip}  (v{ip_version(ip)})")

    # --- HTTP attack patterns (paths) ---
    section("HTTP top paths (10)")
    for p, n in collections.Counter(e.get("path") for e in http).most_common(10):
        print(f"  {n:4d}  {p}")

    section("HTTP top user agents (8)")
    for ua, n in collections.Counter(e.get("user_agent") for e in http).most_common(8):
        print(f"  {n:4d}  {ua!r}")

    # --- UFW: top blocked-port targets ---
    section("UFW: most-probed ports (10)")
    port_counter = collections.Counter(
        (u["proto"], u.get("dpt")) for u in ufw if u.get("dpt")
    )
    for (proto, port), n in port_counter.most_common(10):
        print(f"  {n:4d}  {proto.lower()}/{port}")

    # --- correlation: IPs in BOTH UFW and HoneyCow events ---
    section("Correlated IPs (scanned unlistened ports AND probed HoneyCow)")
    honeycow_ips = set(ext_ips) | set(http_ips)
    ufw_ip_set = set(ufw_ips)
    overlap = sorted(honeycow_ips & ufw_ip_set, key=lambda ip: -(ext_ips[ip] + http_ips[ip] + ufw_ips[ip]))
    if not overlap:
        print("  (none)")
    for ip in overlap[:15]:
        ports = sorted({u.get("dpt") for u in ufw if u["src"] == ip and u.get("dpt")})
        port_preview = ",".join(ports[:6]) + ("…" if len(ports) > 6 else "")
        print(
            f"  {ip:39s}  dns={ext_ips[ip]:3d}  http={http_ips[ip]:3d}  "
            f"ufw={ufw_ips[ip]:3d}  ports=[{port_preview}]",
        )

    # --- CT-log spike check ---
    if cert_issued is not None:
        section(f"CT-log spike check (cert issued {cert_issued.date()})")
        pre = [e for e in ext if e["_ts"] < cert_issued]
        post = [e for e in ext if e["_ts"] >= cert_issued]
        pre_ips = {e["src_ip"] for e in pre}
        post_ips = {e["src_ip"] for e in post}
        new_ips = post_ips - pre_ips
        print(f"  pre-issuance external queries:  {len(pre)} from {len(pre_ips)} IPs")
        print(f"  post-issuance external queries: {len(post)} from {len(post_ips)} IPs")
        print(f"  new IPs only seen post-issuance: {len(new_ips)}")
        for ip in sorted(new_ips, key=lambda ip: -sum(1 for e in post if e["src_ip"] == ip))[:10]:
            ip_queries = [e for e in post if e["src_ip"] == ip]
            sample_qnames = sorted({e.get("qname", "") for e in ip_queries})[:3]
            print(f"    {ip:39s}  {len(ip_queries)}x  {sample_qnames}")


# ---- main ------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--events", required=True, type=Path,
                    help="path to events.jsonl (or a copy of it)")
    ap.add_argument("--ufw", type=Path, default=None,
                    help="optional path to /var/log/ufw.log")
    ap.add_argument("--hours", type=float, default=24.0,
                    help="window of analysis in hours (default 24)")
    ap.add_argument("--cert-issued", type=str, default=None,
                    help="ISO timestamp of recent cert issuance for CT-log spike check")
    ap.add_argument("--our-ips-file", type=Path, default=None,
                    help="file listing our own IPs/CIDRs (one per line, # comments) "
                         "to bucket as self-test rather than external traffic")
    ap.add_argument("--our-ip", action="append", default=[],
                    help="IP or CIDR identifying our own infrastructure "
                         "(repeatable; merged with --our-ips-file)")
    ap.add_argument("--research-cidrs-file", type=Path,
                    default=Path("config/source_exemptions.txt"),
                    help="file listing known-research scanner CIDRs (same format as "
                         "config/source_exemptions.txt) so inbound QR=1 packets can "
                         "be split between scanner probes and reflection-victim shape")
    args = ap.parse_args()

    since = datetime.now(tz=UTC) - timedelta(hours=args.hours)
    cert_issued = None
    if args.cert_issued:
        cert_issued = datetime.fromisoformat(args.cert_issued)
        if cert_issued.tzinfo is None:
            cert_issued = cert_issued.replace(tzinfo=UTC)

    our_nets = load_our_ips(args.our_ips_file, args.our_ip)
    research_nets = load_research_cidrs(
        args.research_cidrs_file if args.research_cidrs_file.exists() else None,
    )

    events = load_events(args.events, since)
    ufw = parse_ufw(args.ufw, since) if args.ufw else []

    print(f"# HoneyCow morning report — window: last {args.hours:g}h "
          f"(since {since.isoformat()})")
    if our_nets:
        print(f"# self-test filter: {len(our_nets)} network(s) loaded")
    if research_nets:
        print(f"# research-CIDR filter: {len(research_nets)} network(s) loaded")
    render(events, ufw, cert_issued, our_nets=our_nets, research_nets=research_nets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
