#!/usr/bin/env python3
"""Render the HoneyCow daily dashboard from the SQLite index.

Produces ONE self-contained HTML file (data embedded as JSON) so it can be
served by a plain static file server — no backend, no daemon, no auth layer.
Interactivity is entirely client-side.

    tools/dashboard.py --db ~/honeycow-analysis/honeycow.db --out dash.html
    tools/dashboard.py --db ... --out ... --dry-run    # print the rubric verdicts

THE RUBRIC lives in one block below on purpose: grading "what makes a day
interesting" is judgement that will need tweaking, and a tweak should be a
one-line edit, not an archaeology expedition. Every day records WHICH rules
fired, so the dashboard can show its own reasoning and you can tell whether a
threshold is behaving.

Thresholds are RELATIVE (ratio to a trailing median) rather than absolute
because the traffic is long-tailed: one 10k-request flood would poison a
mean/stdev band and hide everything after it. Absolute counts are reserved for
signals that are rare-by-nature (CVE-trigger shapes, true reflection-victim
packets), where any occurrence is the point.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path

try:
    from tools.honeycow_digest import ip_in_nets, is_private_or_loopback, load_research_cidrs
except ImportError:
    from honeycow_digest import ip_in_nets, is_private_or_loopback, load_research_cidrs

# ---------------------------------------------------------------------------
# THE RUBRIC — tweak here, nowhere else.
# ---------------------------------------------------------------------------
RUBRIC = {
    # Trailing window used for the "normal" baseline each day is compared to.
    "trailing_days": 28,
    # Relative volume spikes, as a multiple of the trailing median.
    "http_spike_yellow": 3.0,
    "http_spike_red": 10.0,
    "dns_spike_yellow": 2.0,
    "dns_spike_red": 4.0,
    # Exploit-shaped HTTP probing is sadly routine background, so this is a
    # spike test too — not an absolute count.
    "exploit_spike_yellow": 3.0,
    # CVE-trigger recon: a steady ~2/day trickle on a weekly cadence turned out
    # to be one scheduled scanner, not an incident — grading that yellow painted
    # the calendar every Tuesday and taught you to ignore yellow. The count is
    # ALWAYS shown on the day's card; it only drives colour when it exceeds the
    # routine floor. (Principle: colour grades deviation, the panel shows all.)
    "cve_trigger_yellow": 3,
    # Genuinely rare-by-nature: any occurrence is the point.
    "qr_oversized_nonresearch_red": 1,  # true reflection-victim shape
    # A burst of never-before-seen sources suggests a new campaign found us.
    "new_source_spike_yellow": 4.0,
}

EXPLOIT_FAMILIES = ("phpunit-rce", "php-cgi-rce", "apache-traversal", "git-config-leak")

STATUS_RANK = {"green": 0, "yellow": 1, "red": 2}


def _worst(a: str, b: str) -> str:
    return a if STATUS_RANK[a] >= STATUS_RANK[b] else b


def grade_day(day: dict, baseline: dict) -> tuple[str, list[str]]:
    """Return (status, [human-readable reasons]) for one day.

    `baseline` carries the trailing medians this day is judged against.
    """
    status, why = "green", []

    def ratio(n: int, base: float) -> float:
        return (n / base) if base > 0 else 0.0

    r = ratio(day["http"], baseline["http"])
    if r >= RUBRIC["http_spike_red"]:
        status = _worst(status, "red")
        why.append(f"HTTP volume {r:.1f}x the 28-day median ({day['http']:,} vs {baseline['http']:,.0f})")
    elif r >= RUBRIC["http_spike_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"HTTP volume {r:.1f}x the 28-day median ({day['http']:,} vs {baseline['http']:,.0f})")

    r = ratio(day["dns_queries"], baseline["dns"])
    if r >= RUBRIC["dns_spike_red"]:
        status = _worst(status, "red")
        why.append(f"DNS volume {r:.1f}x the 28-day median ({day['dns_queries']:,})")
    elif r >= RUBRIC["dns_spike_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"DNS volume {r:.1f}x the 28-day median ({day['dns_queries']:,})")

    r = ratio(day["exploit"], baseline["exploit"])
    if day["exploit"] and r >= RUBRIC["exploit_spike_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"exploit-shaped HTTP {r:.1f}x baseline ({day['exploit']} probes)")

    if day["cve_trigger"] >= RUBRIC["cve_trigger_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"{day['cve_trigger']} CVE-2026-5946 trigger-shaped quer"
                   f"{'y' if day['cve_trigger'] == 1 else 'ies'} (non-IN class, non-banner)")

    if day["qr_oversized_nonresearch"] >= RUBRIC["qr_oversized_nonresearch_red"]:
        status = _worst(status, "red")
        why.append(f"{day['qr_oversized_nonresearch']} oversized QR=1 packet(s) from a "
                   "non-research source — reflection-victim shape")

    r = ratio(day["new_sources"], baseline["new_sources"])
    if day["new_sources"] and r >= RUBRIC["new_source_spike_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"{day['new_sources']} never-before-seen source IPs ({r:.1f}x baseline)")

    if not why:
        why.append("all volumes within band; probes absorbed by the exemption lists")
    return status, why


def load_narratives(notes_dir: Path | None) -> dict[str, str]:
    """Read per-day prose from `<notes_dir>/YYYY-MM-DD.md`, if present.

    The dashboard is deterministic — it detects, it does not interpret. This is
    the seam where interpretation gets in: a human (or, later, an
    exception-triggered model call on yellow/red days) drops a markdown file
    named for the day and the page renders it above the numbers. Building the
    slot now keeps that choice open without committing to any automation.
    """
    out: dict[str, str] = {}
    if not notes_dir or not notes_dir.is_dir():
        return out
    for p in sorted(notes_dir.glob("*.md")):
        out[p.stem] = p.read_text().strip()
    return out


def build(db_path: Path, notes_dir: Path | None = None) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    research_nets = load_research_cidrs(Path("config/source_exemptions.txt"))
    narratives = load_narratives(notes_dir)

    # --- per-day DNS ---
    days: dict[str, dict] = {}

    def slot(d: str) -> dict:
        return days.setdefault(d, {
            "date": d, "dns_queries": 0, "dns_drops": 0, "dns_external": 0,
            "http": 0, "ufw": None, "exploit": 0, "cve_trigger": 0,
            "qr_oversized_nonresearch": 0, "new_sources": 0,
            "families": {}, "http_families": {}, "sources": {},
            "http_paths": {}, "user_agents": {},
        })

    for r in conn.execute(
        "SELECT substr(ts,1,10) d, event, src_ip, family, drop_reason, src_port, "
        "response_bytes, raw_len FROM dns"
    ):
        s = slot(r["d"])
        ip = r["src_ip"] or ""
        if r["event"] == "query":
            s["dns_queries"] += 1
            if not is_private_or_loopback(ip):
                s["dns_external"] += 1
                s["sources"][ip] = s["sources"].get(ip, 0) + 1
                fam = r["family"] or "other"
                s["families"][fam] = s["families"].get(fam, 0) + 1
                if fam == "cve-2026-5946-trigger":
                    s["cve_trigger"] += 1
        else:
            s["dns_drops"] += 1
            # Inbound QR=1 that is oversized AND not from a known research CIDR
            # is the shape that suggests we're a reflection victim, not a target.
            if r["drop_reason"] == "oversized_datagram" and r["src_port"] == 53:
                if not ip_in_nets(ip, research_nets):
                    s["qr_oversized_nonresearch"] += 1

    for r in conn.execute(
        "SELECT substr(ts,1,10) d, client_ip, src_ip, family, path, user_agent FROM http"
    ):
        s = slot(r["d"])
        s["http"] += 1
        ip = r["client_ip"] or r["src_ip"] or ""
        if ip and not is_private_or_loopback(ip):
            s["sources"][ip] = s["sources"].get(ip, 0) + 1
        fam = r["family"] or "other"
        s["http_families"][fam] = s["http_families"].get(fam, 0) + 1
        if fam in EXPLOIT_FAMILIES:
            s["exploit"] += 1
        if r["path"]:
            s["http_paths"][r["path"]] = s["http_paths"].get(r["path"], 0) + 1
        if r["user_agent"]:
            s["user_agents"][r["user_agent"]] = s["user_agents"].get(r["user_agent"], 0) + 1

    # UFW is only retained ~5 weeks on the VPS, so early days genuinely have no
    # data. Record None (renders as "no data"), never 0 — a false zero would
    # read as "nothing was blocked", which is a different claim entirely.
    for r in conn.execute("SELECT substr(ts,1,10) d, COUNT(*) n FROM ufw GROUP BY d"):
        slot(r["d"])["ufw"] = r["n"]

    ordered = [days[d] for d in sorted(days)]

    # Today is still accumulating, so its totals are not comparable to a full
    # day. Flag it: the card renders "partial" and it is excluded from the
    # trailing baselines so a half-day can't drag the median down.
    today = datetime.now(tz=UTC).date().isoformat()
    for day in ordered:
        day["partial"] = day["date"] >= today

    # --- first-seen sources (drives the "new campaign found us" signal) ---
    seen: set[str] = set()
    for day in ordered:
        fresh = [ip for ip in day["sources"] if ip not in seen]
        day["new_sources"] = len(fresh)
        seen.update(fresh)

    # --- grade each day against its own trailing window ---
    win = RUBRIC["trailing_days"]
    for i, day in enumerate(ordered):
        prior = [p for p in ordered[max(0, i - win):i] if not p["partial"]] or [day]
        baseline = {
            "http": statistics.median([p["http"] for p in prior]),
            "dns": statistics.median([p["dns_queries"] for p in prior]),
            "exploit": max(statistics.median([p["exploit"] for p in prior]), 1),
            "new_sources": max(statistics.median([p["new_sources"] for p in prior]), 1),
        }
        day["status"], day["why"] = grade_day(day, baseline)
        day["baseline"] = {k: round(v, 1) for k, v in baseline.items()}
        day["narrative"] = narratives.get(day["date"], "")

    # --- trim the wide dicts to top-N for embedding ---
    def top(d: dict, n: int) -> list[list]:
        return [[k, v] for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]

    for day in ordered:
        day["sources"] = top(day["sources"], 10)
        day["families"] = top(day["families"], 8)
        day["http_families"] = top(day["http_families"], 8)
        day["http_paths"] = top(day["http_paths"], 8)
        day["user_agents"] = top(day["user_agents"], 5)

    totals = {
        "days": len(ordered),
        "dns": sum(d["dns_queries"] for d in ordered),
        "http": sum(d["http"] for d in ordered),
        "drops": sum(d["dns_drops"] for d in ordered),
        "unique_sources": len(seen),
        "first": ordered[0]["date"] if ordered else None,
        "last": ordered[-1]["date"] if ordered else None,
        "red": sum(1 for d in ordered if d["status"] == "red"),
        "yellow": sum(1 for d in ordered if d["status"] == "yellow"),
        "green": sum(1 for d in ordered if d["status"] == "green"),
    }
    conn.close()
    return {
        "generated": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "rubric": RUBRIC,
        "totals": totals,
        "days": ordered,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render the HoneyCow daily dashboard.")
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=None, help="HTML output path")
    ap.add_argument("--json", type=Path, default=None, help="also write the raw JSON")
    ap.add_argument("--notes", type=Path, default=None,
                    help="directory of per-day narrative markdown (YYYY-MM-DD.md)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print per-day verdicts; write nothing")
    args = ap.parse_args(argv)

    data = build(args.db, args.notes)

    if args.dry_run:
        for d in data["days"]:
            print(f"{d['date']}  {d['status'].upper():6}  "
                  f"dns={d['dns_queries']:<6} http={d['http']:<6} "
                  f"new_ips={d['new_sources']:<4} :: {d['why'][0]}")
        t = data["totals"]
        print(f"\n[dry-run] {t['days']} days — "
              f"green={t['green']} yellow={t['yellow']} red={t['red']}")
        return 0

    if args.json:
        args.json.write_text(json.dumps(data, indent=2))
        print(f"wrote {args.json}", file=sys.stderr)

    if args.out:
        tpl = (Path(__file__).parent / "dashboard_template.html").read_text()
        html = tpl.replace("/*__DATA__*/null", json.dumps(data, separators=(",", ":")))
        args.out.write_text(html)
        print(f"wrote {args.out} ({len(html) / 1024:.0f} KB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
