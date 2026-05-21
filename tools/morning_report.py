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
        --hours 24 --cert-issued 2026-05-20

`--cert-issued` (optional) marks a CT-log expected spike date — the
report compares external DNS query counts before vs after that
timestamp so a fresh-cert ramp is easy to spot.
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

BIND_CHAOS = {"version.bind.", "hostname.bind.", "id.server.", "authors.bind."}


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


def classify_query(qname: str) -> str:
    if not qname:
        return "empty"
    low = qname.lower()
    if low in BIND_CHAOS:
        return "bind-chaos"
    if "asertdnsresearch" in low:
        return "asert-netscout"
    if "shadowserver" in low:
        return "shadowserver"
    if low.endswith(".cybergreen.net.") or low.endswith(".cyberresilience.io."):
        return "open-resolver-test"
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


def render(events: list[dict], ufw: list[dict], cert_issued: datetime | None) -> None:
    queries = [e for e in events if e.get("event") == "query"]
    ext = [e for e in queries if not is_private_or_loopback(e.get("src_ip", ""))]
    drops = [e for e in events if e.get("event") == "query_drop"]
    http = [e for e in events if e.get("event") == "http_closer"]

    section("totals")
    print(f"  events:        {len(events)}")
    print(f"  DNS queries:   {len(queries)} (external: {len(ext)})")
    print(f"  DNS drops:     {len(drops)}")
    print(f"  HTTP closer:   {len(http)}")
    print(f"  UFW log lines: {len(ufw)}")

    # --- v4/v6 split ---
    section("IPv4 vs IPv6")
    ext_ips = collections.Counter(e["src_ip"] for e in ext)
    v4, v6, unk = bucket_v4_v6(ext_ips)
    print(f"  external DNS queries — v4: {v4}  v6: {v6}  other: {unk}")
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

    # --- reflection-attempt traffic ---
    # query_drop events with src_port=53 and DROPPED_QR / oversized_datagram
    # mean: an attacker spoofed honeycow's IP as the source, sent a query
    # to some authoritative NS, and that NS sent its response to us. The
    # NS source IP is the *reflector* (often unwitting); honeycow is the
    # spoofed victim. This is high-signal forensic data — it's literally
    # somebody else's reflection-amplification mapping scan caught in the
    # act, with our IP as the target. Honeycow drops these correctly
    # (QR bit set / >512 bytes), but the *fact that they arrived* is what
    # we want to see.
    section("reflection-attempt traffic (someone spoofed our IP as victim)")
    reflections = [
        e for e in drops
        if e.get("src_port") == 53
        and e.get("drop_reason") in ("DROPPED_QR", "oversized_datagram")
    ]
    if not reflections:
        print("  (none in window)")
    else:
        reflectors = collections.Counter(e["src_ip"] for e in reflections)
        oversized = collections.Counter(
            e["src_ip"] for e in reflections
            if e.get("drop_reason") == "oversized_datagram"
        )
        max_size = max((e.get("raw_len", 0) for e in reflections), default=0)
        print(f"  total response packets: {len(reflections)}")
        print(f"  distinct reflector IPs: {len(reflectors)}")
        print(f"  largest reflected response: {max_size}B  "
              f"({'amplification potential' if max_size > 512 else 'within UDP cap'})")
        print("  top reflectors:")
        for ip, n in reflectors.most_common(10):
            osz = f"  ({oversized[ip]} oversized)" if oversized[ip] else ""
            print(f"    {n:4d}  {ip}{osz}")

    # --- scanner fingerprint families ---
    section("DNS probe families")
    fam = collections.Counter(classify_query(e.get("qname", "")) for e in ext)
    for k, n in fam.most_common():
        print(f"  {n:4d}  {k}")

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
    args = ap.parse_args()

    since = datetime.now(tz=UTC) - timedelta(hours=args.hours)
    cert_issued = None
    if args.cert_issued:
        cert_issued = datetime.fromisoformat(args.cert_issued)
        if cert_issued.tzinfo is None:
            cert_issued = cert_issued.replace(tzinfo=UTC)

    events = load_events(args.events, since)
    ufw = parse_ufw(args.ufw, since) if args.ufw else []

    print(f"# HoneyCow morning report — window: last {args.hours:g}h "
          f"(since {since.isoformat()})")
    render(events, ufw, cert_issued)
    return 0


if __name__ == "__main__":
    sys.exit(main())
