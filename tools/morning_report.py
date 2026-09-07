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
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Parse + classify lives in the shared lib so the central report and the
# cow-side digest emitter agree on every bucket. We import only the names
# this report actually uses; the constants (BIND_CHAOS, etc.) now live
# solely in honeycow_digest — import them from there.
#
# Dual import: as a package (`tools.morning_report`, how the tests load it)
# the repo root is on sys.path; run as a script (`tools/morning_report.py`,
# how `make report` invokes it) only `tools/` is, so fall back to the bare
# module name.
try:
    from tools.honeycow_digest import (
        FLAG_RD,
        bucket_v4_v6,
        classify_http,
        classify_query,
        classify_research_scanner,
        ip_in_nets,
        ip_version,
        is_our_ip,
        is_private_or_loopback,
        load_digests,
        load_events,
        load_our_ips,
        load_research_cidrs,
        merge_digests,
        parse_ufw,
    )
except ImportError:
    from honeycow_digest import (
        FLAG_RD,
        bucket_v4_v6,
        classify_http,
        classify_query,
        classify_research_scanner,
        ip_in_nets,
        ip_version,
        is_our_ip,
        is_private_or_loopback,
        load_digests,
        load_events,
        load_our_ips,
        load_research_cidrs,
        merge_digests,
        parse_ufw,
    )


def section(title: str) -> None:
    print(f"\n=== {title} ===")


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

    # HTTP-side probe taxonomy — twin of "DNS probe families". Names the exploit
    # sweeps hiding in the path list (e.g. Hikvision CVE-2021-36260 recon against
    # /SDK/webLanguage) instead of leaving them as bare paths.
    section("HTTP probe families")
    for k, n in collections.Counter(
        classify_http(e.get("path", "")) for e in http
    ).most_common():
        print(f"  {n:4d}  {k}")

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


# ---- herd render (from merged digests) -------------------------------------

def render_herd(
    merged: dict,
    our_nets: list[ipaddress._BaseNetwork] | None = None,
    research_nets: list[ipaddress._BaseNetwork] | None = None,
) -> None:
    """Render a report from merged per-site digests.

    Mirrors `render()`'s sections for every dimension the digest keeps, so a
    herd report reads like a single-cow one. The our-IP-sensitive sections
    (totals split, families, source-exempt, top sources) are recomputed from
    `by_src` excluding `our_nets`, so `--our-ips` works at merge time exactly
    as it does on raw events. Sections needing per-event detail not carried
    in the digest (CT-log spike) are omitted in herd mode.
    """
    our_nets = our_nets or []
    research_nets = research_nets or []
    by_src = merged["by_src"]
    totals = merged["totals"]

    def _our(ip: str) -> bool:
        return is_our_ip(ip, our_nets)

    ext_ips = collections.Counter(
        {ip: s["dns"] for ip, s in by_src.items() if s["dns"] and not _our(ip)}
    )
    selftest_ips = collections.Counter(
        {ip: s["dns"] for ip, s in by_src.items() if s["dns"] and _our(ip)}
    )
    http_ips = collections.Counter(
        {ip: s["http"] for ip, s in by_src.items() if s["http"]}
    )
    ufw_ips = collections.Counter(
        {ip: s["ufw"] for ip, s in by_src.items() if s["ufw"]}
    )

    # our-sensitive rollups recomputed from by_src so --our-ips is honoured
    families: collections.Counter = collections.Counter()
    source_exempt: collections.Counter = collections.Counter()
    for ip, s in by_src.items():
        if _our(ip):
            continue
        families.update(s["families"])
        n_exempt = s["handlers"].get("exempt_source", 0)
        if n_exempt:
            source_exempt[ip] += n_exempt

    ext_count = sum(ext_ips.values())
    selftest_count = sum(selftest_ips.values())

    section("totals")
    print(f"  events:        {totals.get('events', 0)}")
    if our_nets:
        print(f"  DNS queries:   {totals.get('dns_queries', 0)} "
              f"(external: {ext_count}, self-test: {selftest_count})")
    else:
        print(f"  DNS queries:   {totals.get('dns_queries', 0)} "
              f"(external: {ext_count})")
    print(f"  DNS drops:     {totals.get('dns_drops', 0)}")
    print(f"  HTTP closer:   {totals.get('http', 0)}")
    print(f"  UFW log lines: {totals.get('ufw', 0)}")

    section("IPv4 vs IPv6")
    v4, v6, unk = bucket_v4_v6(ext_ips)
    print(f"  external DNS queries — v4: {v4}  v6: {v6}  other: {unk}")
    if our_nets:
        v4s, v6s, unks = bucket_v4_v6(selftest_ips)
        print(f"  self-test DNS queries — v4: {v4s}  v6: {v6s}  other: {unks}")
    v4h, v6h, unkh = bucket_v4_v6(http_ips)
    print(f"  HTTP closer (client_ip) — v4: {v4h}  v6: {v6h}  other: {unkh}")
    v4u, v6u, unku = bucket_v4_v6(ufw_ips)
    print(f"  UFW blocked  — v4: {v4u}  v6: {v6u}  other: {unku}")
    reached_total, ufw_total = v4 + v6, v4u + v6u
    if reached_total and ufw_total:
        print(f"  v6 ingress check — v6 share of reached DNS: "
              f"{100 * v6 / reached_total:.1f}%  "
              f"v6 share of UFW: {100 * v6u / ufw_total:.1f}%")

    # --- herd-only: cross-vantage fan-out ---
    section("fan-out (sources seen at multiple vantage points)")
    fan = sorted(
        ((ip, sorted(s["sites"])) for ip, s in by_src.items()
         if len(s["sites"]) > 1),
        key=lambda kv: -len(kv[1]),
    )
    sites = merged.get("sites", {})
    print(f"  sites merged: {len(sites)} ({', '.join(sorted(sites)) or 'none'})")
    if not fan:
        print("  (no source seen at >1 site)")
    for ip, where in fan[:15]:
        print(f"    {ip:39s}  {len(where)} sites: {','.join(where)}")

    section("source-IP exemption hits (REFUSED by source CIDR)")
    if not source_exempt:
        print("  (none in window)")
    else:
        print(f"  total: {sum(source_exempt.values())} queries from "
              f"{len(source_exempt)} unique IPs")
        for ip, n in source_exempt.most_common(10):
            print(f"    {n:4d}  {ip}")

    section("DNS probe families")
    # Sort ties by name so a herd report is deterministic regardless of the
    # order digests were merged in.
    for k, n in sorted(families.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {n:4d}  {k}")

    cve = [e for e in merged.get("cve_exemplars", []) if not _our(e.get("src_ip", ""))]
    if cve:
        section("CVE-2026-5946 trigger candidates")
        by_ip = collections.Counter(e["src_ip"] for e in cve)
        print(f"  total: {len(cve)} queries from {len(by_ip)} unique IPs")
        for ip, n in by_ip.most_common(10):
            print(f"    {n:3d}x {ip}")
            for e in [x for x in cve if x["src_ip"] == ip][:3]:
                rd = "RD=1" if e.get("flags", 0) & FLAG_RD else "RD=0"
                print(f"        {e.get('qclass_name', '?')}/"
                      f"{e.get('qtype_name', '?'):<6} {e.get('opcode', '?'):<6} "
                      f"{rd}  {e.get('qname', '')!r}")

    section("research scanners (REFUSED via exemptions, still observed)")
    research = merged.get("research_scanners", {})
    if not research:
        print("  (none in window)")
    for org in sorted(research, key=lambda k: -research[k]["hits"]):
        d = research[org]
        src_ips = collections.Counter(d["src_ips"])
        print(f"  {org:18s}  hits={d['hits']:3d}  refused={d['refused']:3d}  "
              f"src_ips={len(src_ips)}")
        for ip, n in src_ips.most_common(5):
            print(f"      {n:3d}x {ip}")
        for q in sorted(d["qnames"])[:3]:
            print(f"      qname: {q}")

    section("top external DNS sources (10)")
    for ip, n in ext_ips.most_common(10):
        print(f"  {n:4d}  {ip}  (v{ip_version(ip)})")

    section("HTTP top paths (10)")
    for p, n in collections.Counter(merged.get("http_paths", {})).most_common(10):
        print(f"  {n:4d}  {p}")

    # HTTP-side probe taxonomy — twin of "DNS probe families". Derived from the
    # path counts above, so exploit sweeps (e.g. Hikvision CVE-2021-36260 recon
    # against /SDK/webLanguage) read as a named family instead of a bare path.
    section("HTTP probe families")
    http_fam: collections.Counter = collections.Counter()
    for path, n in merged.get("http_paths", {}).items():
        http_fam[classify_http(path)] += n
    for k, n in http_fam.most_common():
        print(f"  {n:4d}  {k}")

    section("HTTP top user agents (8)")
    for ua, n in collections.Counter(
        merged.get("http_user_agents", {})
    ).most_common(8):
        print(f"  {n:4d}  {ua!r}")

    section("UFW: most-probed ports (10)")
    for port, n in collections.Counter(merged.get("ufw_ports", {})).most_common(10):
        print(f"  {n:4d}  {port}")

    section("Correlated IPs (scanned unlistened ports AND probed HoneyCow)")
    honeycow_ips = set(ext_ips) | set(http_ips)
    overlap = sorted(
        honeycow_ips & set(ufw_ips),
        key=lambda ip: -(ext_ips[ip] + http_ips[ip] + ufw_ips[ip]),
    )
    if not overlap:
        print("  (none)")
    for ip in overlap[:15]:
        ports = sorted(by_src[ip]["ufw_ports"])
        preview = ",".join(ports[:6]) + ("…" if len(ports) > 6 else "")
        print(f"  {ip:39s}  dns={ext_ips[ip]:3d}  http={http_ips[ip]:3d}  "
              f"ufw={ufw_ips[ip]:3d}  ports=[{preview}]")


# ---- main ------------------------------------------------------------------

def load_from_db(
    db_path: Path, since: datetime,
) -> tuple[list[dict], list[dict]]:
    """Load events + UFW rows from the SQLite index (tools/ingest.py) in the
    same dict shapes ``load_events`` / ``parse_ufw`` produce, so ``render`` is
    agnostic to whether the data came from raw files or the index.

    Rows are ordered by (ts_epoch, rowid) to reproduce raw-file (chronological,
    then insertion) order, which keeps Counter.most_common tie-breaks — and thus
    the rendered output — identical to the direct-from-raw report.
    """
    since_epoch = since.timestamp()
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    events: list[dict] = []
    try:
        for r in conn.execute(
            "SELECT * FROM dns WHERE ts_epoch >= ? ORDER BY ts_epoch, rowid",
            (since_epoch,),
        ):
            e = {
                "event": r["event"], "src_ip": r["src_ip"],
                "src_port": r["src_port"], "transport": r["transport"],
                "qname": r["qname"], "qtype_name": r["qtype"],
                "qclass_name": r["qclass"], "opcode": r["opcode"],
                "rcode": r["rcode"], "response_kind": r["response_kind"],
                "handler": r["handler"], "drop_reason": r["drop_reason"],
                "flags": r["flags"], "ts": r["ts"],
            }
            if r["ts"]:
                e["_ts"] = datetime.fromisoformat(r["ts"])
            events.append(e)
        for r in conn.execute(
            "SELECT * FROM http WHERE ts_epoch >= ? ORDER BY ts_epoch, rowid",
            (since_epoch,),
        ):
            e = {
                "event": "http_closer", "src_ip": r["src_ip"],
                "client_ip": r["client_ip"], "method": r["method"],
                "path": r["path"], "host": r["host"],
                "user_agent": r["user_agent"], "ts": r["ts"],
            }
            if r["ts"]:
                e["_ts"] = datetime.fromisoformat(r["ts"])
            events.append(e)
        ufw: list[dict] = []
        for r in conn.execute(
            "SELECT * FROM ufw WHERE ts_epoch >= ? ORDER BY ts_epoch, rowid",
            (since_epoch,),
        ):
            ts = r["ts"]
            ufw.append({
                "src": r["src"], "dst": r["dst"], "proto": r["proto"],
                # parse_ufw yields dpt as a string; mirror that so port
                # Counters/sorts match the raw path exactly.
                "dpt": str(r["dpt"]) if r["dpt"] is not None else None,
                "verdict": r["verdict"],
                "ts": datetime.fromisoformat(ts) if ts else None,
            })
    finally:
        conn.close()
    return events, ufw


def load_promotions(path: Path | None, since: datetime) -> list[dict]:
    """New CVE signatures ruminate promoted into the taxonomy inside the window.

    Cross-repo seam: `ruminate/scripts/weekly-scan.sh` appends one JSON object
    per promotion to `state/promotions.jsonl`. Promotion is automatic — the
    manual review gate stalled for months — so the report is where a new
    signature announces itself. Best-effort by design: a missing or malformed
    promotions file must never cost you the rest of the report.
    """
    if not path or not path.is_file():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            day = datetime.fromisoformat(rec["date"]).replace(tzinfo=UTC)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue
        if day >= since.replace(hour=0, minute=0, second=0, microsecond=0):
            out.append(rec)
    return out


def render_promotions(promotions: list[dict]) -> None:
    if not promotions:
        return
    section("new CVE signatures added to the taxonomy (ruminate)")
    print(f"  {len(promotions)} promoted in window — honeycow now matches these shapes")
    for rec in promotions[:20]:
        title = rec.get("title") or "(no title)"
        print(f"    {rec.get('date', '?')}  {rec.get('cve_id', '?'):<18} {title[:60]}")
    if len(promotions) > 20:
        print(f"    ...and {len(promotions) - 20} more")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--events", type=Path, default=None,
                    help="path to events.jsonl (or a copy of it)")
    ap.add_argument("--db", type=Path, default=None,
                    help="read from a SQLite index built by tools/ingest.py "
                         "instead of raw events (indexed time-window; UFW comes "
                         "from the index too, so --ufw is ignored)")
    ap.add_argument("--herd", type=Path, nargs="+", default=None,
                    metavar="PATH",
                    help="merge per-site digest.jsonl files/dirs instead of "
                         "reading raw events (the collector-side herd report)")
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
    ap.add_argument("--promotions", type=Path,
                    default=Path.home() / "projects/ruminate/state/promotions.jsonl",
                    help="ruminate promotions log; new CVE signatures added in the "
                         "window are announced in the report (best-effort)")
    args = ap.parse_args()

    modes = [args.events is not None, args.db is not None, args.herd is not None]
    if sum(modes) != 1:
        ap.error("specify exactly one of --events (raw), --db (SQLite index), "
                 "or --herd (digests)")

    our_nets = load_our_ips(args.our_ips_file, args.our_ip)
    research_nets = load_research_cidrs(
        args.research_cidrs_file if args.research_cidrs_file.exists() else None,
    )

    if args.herd is not None:
        digests = load_digests(args.herd)
        merged = merge_digests(digests)
        print(f"# HoneyCow herd report — {len(digests)} digest line(s) "
              f"from {len(merged['sites'])} site(s)")
        if our_nets:
            print(f"# self-test filter: {len(our_nets)} network(s) loaded")
        if research_nets:
            print(f"# research-CIDR filter: {len(research_nets)} network(s) loaded")
        render_herd(merged, our_nets=our_nets, research_nets=research_nets)
        return 0

    since = datetime.now(tz=UTC) - timedelta(hours=args.hours)
    cert_issued = None
    if args.cert_issued:
        cert_issued = datetime.fromisoformat(args.cert_issued)
        if cert_issued.tzinfo is None:
            cert_issued = cert_issued.replace(tzinfo=UTC)

    if args.db is not None:
        events, ufw = load_from_db(args.db, since)
    else:
        events = load_events(args.events, since)
        ufw = parse_ufw(args.ufw, since) if args.ufw else []

    print(f"# HoneyCow morning report — window: last {args.hours:g}h "
          f"(since {since.isoformat()})")
    if our_nets:
        print(f"# self-test filter: {len(our_nets)} network(s) loaded")
    if research_nets:
        print(f"# research-CIDR filter: {len(research_nets)} network(s) loaded")
    render(events, ufw, cert_issued, our_nets=our_nets, research_nets=research_nets)
    render_promotions(load_promotions(args.promotions, since))
    return 0


if __name__ == "__main__":
    sys.exit(main())
