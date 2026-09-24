#!/usr/bin/env python3
"""Build the nameserver query index from pulled BIND logs.

Runs on the REPORT host. Reads `<analysis>/ns/<host>/queries.log*` (and the
pre-true-up `named.log.*` syslog history) and writes a DuckDB table.

    tools/ingest_ns.py --dry-run
    tools/ingest_ns.py --db ~/honeycow-analysis/ns.duckdb

WHY DUCKDB AND NOT THE EXISTING SQLITE INDEX. Two measured reasons and one
structural one. Measured at 13.3M rows: the corpus is 0.22 GB columnar against
1.74 GB in SQLite, and the full-table scans this sensor exists for run in
0.24-0.46s against 23-35s. Structural: DuckDB ATTACHes honeycow.db read-only,
so the cross-sensor join needs no migration, no second copy of honeycow's data
and no change to `ingest.py`. SQLite stays the store of record for the
honeypot; this is a reader beside it, not a replacement.

The honeypot image never sees this — `duckdb` lives in requirements-analysis.txt.

IDEMPOTENCY. BIND rotates rather than appending, so a byte-offset watermark is
meaningless across a rotation, and a timestamp watermark silently drops rows
that share the boundary millisecond. Instead each (host, day) touched by the
input is deleted and rewritten whole. Re-running over overlapping pulls is
therefore free of double-counting, which is the same guarantee `ingest.py`
gets from its rowhash — bought here with a partition drop, because a per-row
hash cost 6x the load time and 0.8 GB when measured against a table this size.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import tempfile
from pathlib import Path

MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

# Both formats share everything from `client @` onward; only the timestamp
# prefix differs, so the body is parsed once.
#   file channel (current, all hosts):
#     13-Mar-2026 03:11:44.539 queries: info: client @0x7.. IP#port (NAME): query: NAME IN A -E(0)DC (dest)
#   syslog channel (ns1/ns2 before the 2026-08-01 true-up):
#     2026-07-26T00:00:17.597399+00:00 host named[63297]: client @0x7.. IP#port (NAME): query: ...
_BODY = re.compile(
    r"client @0x[0-9a-f]+ (?P<src>\S+?)#(?P<port>\d+) \((?P<asked>[^)]*)\): "
    r"query: (?P<qname>\S+) (?P<qclass>\S+) (?P<qtype>\S+)(?: (?P<flags>\S+))?"
)
_FILE_TS = re.compile(r"^(\d{2})-([A-Z][a-z]{2})-(\d{4}) (\d{2}:\d{2}:\d{2})\.(\d{3})")
_SYSLOG_TS = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})\.(\d+)")


def parse_line(line: str) -> tuple | None:
    """-> (ts, day, src_ip, asked_name, qname, qclass, qtype, flags) or None.

    `asked_name` keeps the original casing: resolvers apply DNS 0x20 randomised
    capitalisation as an off-path spoofing defence, so the difference between
    it and the lowercased qname is a real signal about who is asking, not noise
    to normalise away.
    """
    m = _FILE_TS.match(line)
    if m:
        d, mon, y, hms, frac = m.groups()
        if mon not in MONTHS:
            return None
        day = f"{y}-{MONTHS[mon]:02d}-{d}"
    else:
        m = _SYSLOG_TS.match(line)
        if not m:
            return None
        y, mo, d, hms, frac = m.groups()
        day = f"{y}-{mo}-{d}"
    b = _BODY.search(line)
    if not b:
        return None
    return (f"{day}T{hms}.{frac[:3]}", day, b["src"], b["asked"],
            b["qname"].rstrip(".").lower(), b["qclass"], b["qtype"],
            b["flags"] or "")


SCHEMA = """
CREATE TABLE IF NOT EXISTS ns_queries (
    host      VARCHAR,   -- which vantage point saw it
    ts        VARCHAR,
    day       VARCHAR,
    src_ip    VARCHAR,
    asked     VARCHAR,   -- qname as sent, 0x20 casing preserved
    qname     VARCHAR,   -- lowercased, trailing dot stripped
    qclass    VARCHAR,
    qtype     VARCHAR,
    flags     VARCHAR
);
CREATE TABLE IF NOT EXISTS ns_files (
    host        VARCHAR,
    name        VARCHAR,
    fingerprint VARCHAR   -- size:mtime, so a rotated file re-reads once
);
"""


def log_files(root: Path, host: str) -> list[Path]:
    d = root / host
    if not d.is_dir():
        return []
    return sorted([p for p in d.iterdir()
                   if p.is_file() and (p.name.startswith("queries.log")
                                       or p.name.startswith("named.log."))])


def read_rows(paths: list[Path], host: str):
    """Yield parsed rows, counting what could not be parsed."""
    good = bad = 0
    for p in paths:
        opener = open
        if p.suffix == ".gz":
            import gzip
            opener = gzip.open
        try:
            with opener(p, "rt", errors="replace") as f:
                for line in f:
                    if " query: " not in line:
                        continue  # responses/xfer/notify share these channels
                    row = parse_line(line)
                    if row:
                        good += 1
                        yield (host,) + row
                    else:
                        bad += 1
        except OSError as exc:
            print(f"ingest-ns: cannot read {p}: {exc}", file=sys.stderr)
    read_rows.stats[host] = (good, bad)


read_rows.stats = {}

# Rows per executemany. Large enough that per-call overhead disappears, small
# enough that the buffer stays a rounding error against the corpus.
COLUMNS = ("{'host':'VARCHAR','ts':'VARCHAR','day':'VARCHAR','src_ip':'VARCHAR',"
           "'asked':'VARCHAR','qname':'VARCHAR','qclass':'VARCHAR',"
           "'qtype':'VARCHAR','flags':'VARCHAR'}")


def _fingerprint(path: Path) -> str:
    st = path.stat()
    return f"{st.st_size}:{int(st.st_mtime)}"


def seen(con, host: str, path: Path, force: bool) -> bool:
    """Has this exact file (name + size + mtime) already been ingested?"""
    if force:
        return False
    row = con.execute(
        "SELECT fingerprint FROM ns_files WHERE host = ? AND name = ?",
        [host, path.name]).fetchone()
    return bool(row) and row[0] == _fingerprint(path)


def remember(con, host: str, path: Path) -> None:
    con.execute("DELETE FROM ns_files WHERE host = ? AND name = ?", [host, path.name])
    con.execute("INSERT INTO ns_files VALUES (?, ?, ?)",
                [host, path.name, _fingerprint(path)])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Index BIND query logs into DuckDB.")
    analysis = Path(os.environ.get("HONEYCOW_ANALYSIS_DIR",
                                   Path.home() / "honeycow-analysis"))
    ap.add_argument("--logs", type=Path, default=analysis / "ns")
    ap.add_argument("--db", type=Path, default=analysis / "ns.duckdb")
    ap.add_argument("--hosts", default=os.environ.get("HONEYCOW_NS_HOSTS", "ns1 ns2 ns3"))
    ap.add_argument("--rebuild", action="store_true", help="drop and rebuild the table")
    ap.add_argument("--force", action="store_true",
                    help="re-read files even if unchanged since last ingest")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report, write nothing")
    args = ap.parse_args(argv)

    hosts = args.hosts.split()
    if not args.logs.is_dir():
        print(f"ingest-ns: no log dir at {args.logs} — run tools/pull-ns-logs.sh first",
              file=sys.stderr)
        return 1

    if args.dry_run:
        total = 0
        for host in hosts:
            paths = log_files(args.logs, host)
            rows = sum(1 for _ in read_rows(paths, host))
            good, bad = read_rows.stats.get(host, (0, 0))
            total += rows
            print(f"[dry-run] {host}: {len(paths)} file(s), {good:,} queries parsed, "
                  f"{bad:,} unparsed")
        print(f"[dry-run] {total:,} rows would be written to {args.db}")
        return 0

    import duckdb
    args.db.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(args.db))
    if args.rebuild:
        con.execute("DROP TABLE IF EXISTS ns_queries")
        con.execute("DROP TABLE IF EXISTS ns_files")
    con.execute(SCHEMA)

    written = 0
    for host in hosts:
        paths = log_files(args.logs, host)
        if not paths:
            print(f"ingest-ns: no logs for {host}", file=sys.stderr)
            continue
        # Skip files already ingested unchanged. BIND rotation renames files,
        # so identity is (name, size, mtime) rather than a byte offset — a
        # rotated file gets a new name and is re-read once, which is correct.
        # Without this every 4-hourly run re-parses the whole 2.5 GB corpus.
        fresh = [q for q in paths if not seen(con, host, q, args.force)]
        if not fresh:
            print(f"ingest-ns: {host}: no changed files", file=sys.stderr)
            continue

        # ONE PASS, VIA CSV. Rows stream straight to a scratch CSV and DuckDB
        # bulk-loads it. Both halves of that are deliberate and measured.
        #
        # Streaming, because the obvious group-by-day buffer reached 1.5 GB
        # resident and climbing on ns3's 9.2M rows, on a 7.8 GB host.
        #
        # CSV rather than executemany, because DuckDB's row-at-a-time insert
        # path is its pathological case: at 13.3M rows it had not finished ns1
        # after 19 minutes, where writing the CSV took 30s and `read_csv`
        # ingested it in 15s. Feeding a columnar engine one row at a time
        # throws away the only thing it is good at.
        with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="",
                                         delete=False) as fh:
            scratch = Path(fh.name)
            w = csv.writer(fh)
            for row in read_rows(fresh, host):
                w.writerow(row)
        good, bad = read_rows.stats.get(host, (0, 0))
        try:
            con.execute("BEGIN")
            con.execute(
                "CREATE OR REPLACE TEMP TABLE staging AS SELECT * FROM "
                f"read_csv('{scratch}', columns={COLUMNS}, header=false)")
            stats = con.execute(
                "SELECT COUNT(*), COUNT(DISTINCT day), MIN(day), MAX(day) FROM staging"
            ).fetchone()
            if not stats[0]:
                con.execute("ROLLBACK")
                continue
        # Partition replace: every (host, day) present in this input is
        # rewritten whole, so an overlapping re-pull cannot double-count.
            con.execute("DELETE FROM ns_queries WHERE host = ? AND day IN "
                        "(SELECT DISTINCT day FROM staging)", [host])
            con.execute("INSERT INTO ns_queries SELECT * FROM staging")
            for q in fresh:
                remember(con, host, q)
            con.execute("COMMIT")
        finally:
            scratch.unlink(missing_ok=True)
        written += stats[0]
        print(f"ingest-ns: {host}: {stats[0]:,} queries over {stats[1]} days "
              f"({stats[2]} .. {stats[3]}), {bad:,} unparsed, "
              f"{len(fresh)}/{len(paths)} file(s) read", file=sys.stderr)

    n = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    con.execute("CHECKPOINT")
    con.close()
    size = args.db.stat().st_size / 1e9
    print(f"ingest-ns: wrote {written:,} rows; table now {n:,} rows, "
          f"{size:.2f} GB at {args.db}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
