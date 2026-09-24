#!/usr/bin/env python3
"""Measure how much of honeycow's traffic is ambient internet background.

Runs on the REPORT host against both indexes at once: the DuckDB nameserver
table and honeycow's SQLite, ATTACHed read-only.

    tools/ns_ambient.py
    tools/ns_ambient.py --json

WHAT THIS ANSWERS. Every model-written note in `notes/` ends with some form of
"this is v4-wide sweeping, not aimed at us." It is the most repeated claim in
the corpus and, until now, always an inference from path shapes and user-agent
strings. ns1-3 answer it directly: they are advertised in the .net delegation,
serve real zones, and have nothing to do with honeycow — so a source that hits
both is sweeping the internet, and a source that hits only honeycow is not.

`ambient_pct` is the share of a day's honeycow sources that a real nameserver
also saw. A HIGH value means a loud day was commodity weather. A LOW value on
a loud day is the genuinely interesting case, and it is exactly the case the
current rubric cannot see — every rule it has measures volume or shape at
honeycow alone.

This is a measurement, not an interpretation: it counts source IPs observed by
an independent sensor. That distinction is what would let it drive colour,
where a note never can.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

AMBIENT_SQL = """
WITH hc AS (
    SELECT substr(ts, 1, 10) AS day, src_ip
    FROM hc.dns
    WHERE src_ip IS NOT NULL AND event = 'query'
    GROUP BY 1, 2
),
ns AS (
    SELECT day, src_ip FROM ns_queries GROUP BY 1, 2
),
ns_day AS (
    SELECT day, COUNT(*) AS ns_sources FROM ns GROUP BY 1
)
SELECT hc.day,
       COUNT(*)                                        AS hc_sources,
       COALESCE(MAX(ns_day.ns_sources), 0)             AS ns_sources,
       COUNT(ns.src_ip)                                AS overlap,
       ROUND(100.0 * COUNT(ns.src_ip) / COUNT(*), 1)   AS ambient_pct
FROM hc
LEFT JOIN ns      ON ns.day = hc.day AND ns.src_ip = hc.src_ip
LEFT JOIN ns_day  ON ns_day.day = hc.day
GROUP BY hc.day
HAVING COALESCE(MAX(ns_day.ns_sources), 0) > 0   -- only days both sensors cover
ORDER BY hc.day
"""

COVERAGE_SQL = """
SELECT host, MIN(day) AS first_day, MAX(day) AS last_day,
       COUNT(*) AS queries, COUNT(DISTINCT src_ip) AS sources
FROM ns_queries GROUP BY host ORDER BY host
"""


def connect(ns_db: Path, honeycow_db: Path):
    import duckdb
    if not ns_db.exists():
        print(f"ns-ambient: no index at {ns_db} — run tools/ingest_ns.py first",
              file=sys.stderr)
        return None
    con = duckdb.connect(str(ns_db), read_only=True)
    con.execute("INSTALL sqlite; LOAD sqlite;")
    # Read-only on purpose: honeycow.db is the honeypot's store of record and
    # this tool has no business writing to it.
    con.execute(f"ATTACH '{honeycow_db}' AS hc (TYPE SQLITE, READ_ONLY)")
    return con


def main(argv: list[str] | None = None) -> int:
    analysis = Path(os.environ.get("HONEYCOW_ANALYSIS_DIR",
                                   Path.home() / "honeycow-analysis"))
    ap = argparse.ArgumentParser(description="Per-day ambient-background fraction.")
    ap.add_argument("--db", type=Path, default=analysis / "ns.duckdb")
    ap.add_argument("--honeycow-db", type=Path, default=analysis / "honeycow.db")
    ap.add_argument("--json", action="store_true", help="emit rows as JSON")
    args = ap.parse_args(argv)

    con = connect(args.db, args.honeycow_db)
    if con is None:
        return 1

    cov = con.execute(COVERAGE_SQL).fetchall()
    rows = con.execute(AMBIENT_SQL).fetchall()
    con.close()

    if args.json:
        print(json.dumps([
            {"day": r[0], "hc_sources": r[1], "ns_sources": r[2],
             "overlap": r[3], "ambient_pct": r[4]} for r in rows], indent=1))
        return 0

    print("nameserver coverage")
    print(f"  {'host':6}{'first':>12}{'last':>12}{'queries':>12}{'sources':>10}")
    for h, a, b, q, s in cov:
        print(f"  {h:6}{a:>12}{b:>12}{q:>12,}{s:>10,}")

    if not rows:
        print("\nno overlapping days — the two sensors cover different periods")
        return 0

    amb = [r[4] for r in rows]
    print(f"\nambient fraction over {len(rows)} days both sensors cover")
    print(f"  min {min(amb):.1f}%   median {sorted(amb)[len(amb)//2]:.1f}%   "
          f"max {max(amb):.1f}%")
    print(f"\n  {'day':12}{'hc_src':>8}{'ns_src':>9}{'overlap':>9}{'ambient':>9}")
    for r in rows[-21:]:
        bar = "#" * int(r[4] / 5)
        print(f"  {r[0]:12}{r[1]:>8}{r[2]:>9,}{r[3]:>9}{r[4]:>8.1f}%  {bar}")
    if len(rows) > 21:
        print(f"  ... {len(rows) - 21} earlier day(s) not shown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
