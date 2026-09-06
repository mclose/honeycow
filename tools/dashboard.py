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
    # The OTHER half of reflection. qr_oversized only sees QR=1 packets
    # *arriving*; it is blind to the QR=0 flood that makes us the reflector.
    # A real resolver picks a fresh transaction id and source port per query,
    # so many queries sharing ONE (src_ip, txid, src_port) tuple means a
    # spoofed source — the named IP is the victim, not the sender.
    #
    # 20 is a measured floor, not a guess. Over 100 days the tuple-group size
    # distribution is: 167 groups at 2-4 (ordinary retries, which legitimately
    # reuse txid+port), 4 at 5-9, 29 at 10-19 (all one slow scanner range,
    # 216.180.246.0/24, spread over 50-120s), then NOTHING until a single group
    # at 74 and a single group at 831. The gap between 19 and 74 is where this
    # line belongs.
    "reflection_burst_min_packets": 20,
    "reflection_burst_red": 1,
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

    # Colour is driven only by bursts we ANSWERED — that is when honeycow
    # actually functioned as a reflector. A burst we refused still gets a line
    # in `why` (the panel shows everything) but must not paint the day red:
    # the defenses working is not a deviation.
    answered = [b for b in day["reflection_bursts"] if b["answered"]]
    refused = [b for b in day["reflection_bursts"] if not b["answered"]]
    if len(answered) >= RUBRIC["reflection_burst_red"]:
        status = _worst(status, "red")
    for b in (answered + refused)[:3]:
        rate = f", {b['n'] / b['span_s']:.0f}/s" if b["span_s"] >= 1 else ""
        verb = "answered" if b["answered"] else "REFUSED"
        emitted = (f", {b['out_bytes'] / 1024:.0f} KB emitted"
                   if b["answered"] and b["out_bytes"] else "")
        why.append(
            f"{b['n']} {verb} {b['qtype'] or '?'} queries from {b['src_ip']} sharing one "
            f"transaction id + source port over {b['span_s']:.1f}s{rate}{emitted} "
            f"— spoofed-source reflection shape"
        )
    if len(day["reflection_bursts"]) > 3:
        why.append(f"...and {len(day['reflection_bursts']) - 3} more reflection-shaped burst(s)")

    r = ratio(day["new_sources"], baseline["new_sources"])
    if day["new_sources"] and r >= RUBRIC["new_source_spike_yellow"]:
        status = _worst(status, "yellow")
        why.append(f"{day['new_sources']} never-before-seen source IPs ({r:.1f}x baseline)")

    if not why:
        why.append("all volumes within band; probes absorbed by the exemption lists")
    return status, why


def load_narratives(notes_dir: Path | None) -> dict[str, dict]:
    """Read per-day prose from `<notes_dir>/YYYY-MM-DD.md`, if present.

    The dashboard is deterministic — it detects, it does not interpret. This is
    the seam where interpretation gets in: a note file named for the day is
    rendered above the numbers. `tools/annotate.py` fills that slot
    automatically for non-green days; a human can drop one in by hand for any
    day. Either way the note NEVER feeds a grade — colour stays earned by
    counted evidence.

    Optional frontmatter carries provenance so the page can say who wrote it:

        ---
        source: model
        model: claude-opus-5
        generated: 2026-09-06T15:40:00+00:00
        ---

    A file with no frontmatter is treated as hand-written, which is the right
    default: every note that predates the annotator was typed by a person.
    """
    out: dict[str, dict] = {}
    if not notes_dir or not notes_dir.is_dir():
        return out
    for p in sorted(notes_dir.glob("*.md")):
        raw = p.read_text().strip()
        meta: dict[str, str] = {}
        if raw.startswith("---\n"):
            head, sep, body = raw[4:].partition("\n---")
            if sep:
                for line in head.splitlines():
                    k, _, v = line.partition(":")
                    if v:
                        meta[k.strip()] = v.strip()
                raw = body.lstrip("\n-").strip() or body.strip()
        if not raw:
            continue
        out[p.stem] = {
            "text": raw,
            "source": meta.get("source", "human"),
            "model": meta.get("model", ""),
            "generated": meta.get("generated", ""),
        }
    return out


def annotator_health(days: list[dict], notes_dir: Path | None) -> dict:
    """Is the note pipeline actually alive?

    Two independent signals, on purpose. `_status.json` is what the annotator
    says about its own last run — useful, but it goes stale silently if the
    tool never runs at all. `missing` is computed here from the graded days and
    the notes on disk, so it stays true even if the annotator is completely
    dead. The operator may not look at this for weeks; the page has to be able
    to say "nothing has interpreted these days" without being told.
    """
    health: dict = {"last_run": "", "ok": None, "error": "", "missing": []}
    if notes_dir and (sf := notes_dir / "_status.json").is_file():
        try:
            st = json.loads(sf.read_text())
            health.update({"last_run": st.get("last_run", ""), "ok": st.get("ok"),
                           "error": st.get("error") or ""})
        except (OSError, json.JSONDecodeError):
            health["error"] = "unreadable _status.json"
    health["missing"] = [d["date"] for d in days
                         if d["status"] != "green" and not d["partial"] and not d["narrative"]]
    return health


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
            "reflection_bursts": [],
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

    # --- reflection-shaped bursts: many queries, one frozen (txid, src_port) ---
    # Done as its own GROUP BY rather than inside the row scan above because the
    # signal IS the grouping. Ordinary retries share a tuple too, which is why
    # the floor matters; see RUBRIC["reflection_burst_min_packets"].
    for r in conn.execute(
        "SELECT substr(ts,1,10) d, src_ip, dns_id, src_port, qtype, COUNT(*) n, "
        "SUM(CASE WHEN decision='respond' THEN 1 ELSE 0 END) answered, "
        "SUM(COALESCE(response_bytes,0)) out_bytes, "
        "(julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0 span_s "
        "FROM dns WHERE event='query' AND src_ip IS NOT NULL AND dns_id IS NOT NULL "
        "GROUP BY d, src_ip, dns_id, src_port HAVING COUNT(*) >= ?",
        (RUBRIC["reflection_burst_min_packets"],),
    ):
        if is_private_or_loopback(r["src_ip"] or ""):
            continue  # our own healthcheck/self-tests, not a reflection victim
        slot(r["d"])["reflection_bursts"].append({
            "src_ip": r["src_ip"], "qtype": r["qtype"], "n": r["n"],
            "answered": bool(r["answered"]), "out_bytes": r["out_bytes"] or 0,
            "span_s": r["span_s"] or 0.0,
        })

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
        day["narrative"] = narratives.get(day["date"])

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
        "annotator": annotator_health(ordered, notes_dir),
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
