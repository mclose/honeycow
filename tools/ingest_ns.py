#!/usr/bin/env python3
"""Build the nameserver query index from pulled BIND and PowerDNS logs.

Runs on the REPORT host. Reads `<analysis>/ns/<host>/queries.log*` (and the
pre-true-up `named.log.*` syslog history) from the BIND hosts, plus
`pdns-queries.<day>.log` from the PowerDNS host, and writes a DuckDB table.

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
# PowerDNS (pdns-nyc2), log-dns-queries=yes, pulled from journald as UTC
# short-iso-precise, so the timestamp is the syslog shape above:
#   ... pdns_server[773]: Remote 138.197.31.10<-8.8.8.0/24 wants 'split.ecs.lab...|A', do = 1, bufsize = 1232 (4096): packetcache MISS
# `<-subnet` is the EDNS Client Subnet a resolver passed along; `(4096)` is the
# client's advertised buffer when PowerDNS capped it. No class, no port.
_PDNS_BODY = re.compile(
    r"Remote (?P<src>[^\s<]+)(?:<-(?P<ecs>\S+))? wants '(?P<asked>.*)\|(?P<qtype>[^|']+)', "
    r"do = (?P<do>\d), bufsize = (?P<buf>\d+)(?: \((?P<cbuf>\d+)\))?"
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
        p = _PDNS_BODY.search(line)
        if not p:
            return None
        # BIND's flags column ("+E(0)DC") has no PowerDNS equivalent; carry
        # the fields PowerDNS does log, in a form a LIKE/regexp can pick out.
        flags = f"do={p['do']} bufsize={p['cbuf'] or p['buf']}"
        if p["ecs"]:
            flags += f" ecs={p['ecs']}"
        return (f"{day}T{hms}.{frac[:3]}", day, p["src"], p["asked"],
                p["asked"].rstrip(".").lower(), "", p["qtype"], flags)
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
-- The days a file covers, so a partition replace can find the unchanged
-- neighbour that shares its boundary day. NULL on rows from before this
-- existed, which counts as "might overlap" and is filled in on first re-read.
ALTER TABLE ns_files ADD COLUMN IF NOT EXISTS min_day VARCHAR;
ALTER TABLE ns_files ADD COLUMN IF NOT EXISTS max_day VARCHAR;
"""


def log_files(root: Path, host: str) -> list[Path]:
    d = root / host
    if not d.is_dir():
        return []
    return sorted([p for p in d.iterdir()
                   if p.is_file() and (p.name.startswith("queries.log")
                                       or p.name.startswith("named.log.")
                                       or p.name.startswith("pdns-queries."))])


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
                    if " query: " not in line and " wants '" not in line:
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


def remember(con, host: str, path: Path, span: tuple[str, str] | None) -> None:
    con.execute("DELETE FROM ns_files WHERE host = ? AND name = ?", [host, path.name])
    # A file with no query lines (ns3's named.log.* hold only other channels)
    # covers no day: "-" sorts below every date, so it is never a neighbour.
    lo, hi = span or ("-", "-")
    con.execute("INSERT INTO ns_files (host, name, fingerprint, min_day, max_day) "
                "VALUES (?, ?, ?, ?, ?)", [host, path.name, _fingerprint(path), lo, hi])


def stored_span(con, host: str, path: Path) -> tuple[str, str] | None:
    row = con.execute("SELECT min_day, max_day FROM ns_files WHERE host = ? AND name = ?",
                      [host, path.name]).fetchone()
    return (row[0], row[1]) if row and row[0] else None


def _copy_rows(path: Path, host: str, w, only: set[str] | None, counts: list[int],
               seen_days: set[str] | None = None):
    """Write one file's rows to the CSV writer -> (min_day, max_day) or None.

    `only` limits what is written (a neighbour contributes only the days being
    replaced); the span returned always covers the whole file. Days written
    are added to `seen_days`."""
    lo = hi = None
    for row in read_rows([path], host):
        day = row[2]
        lo = day if lo is None or day < lo else lo
        hi = day if hi is None or day > hi else hi
        if only is None or day in only:
            w.writerow(row)
            counts[0] += 1
            if seen_days is not None:
                seen_days.add(day)
    counts[1] += read_rows.stats.get(host, (0, 0))[1]
    return (lo, hi) if lo else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Index BIND query logs into DuckDB.")
    analysis = Path(os.environ.get("HONEYCOW_ANALYSIS_DIR",
                                   Path.home() / "honeycow-analysis"))
    ap.add_argument("--logs", type=Path, default=analysis / "ns")
    ap.add_argument("--db", type=Path, default=analysis / "ns.duckdb")
    ap.add_argument("--hosts", default=os.environ.get("HONEYCOW_NS_HOSTS",
                                                "ns1 ns2 ns3 pdns-nyc2"))
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
        #
        # NEIGHBOURS. The partition replace below deletes every (host, day) the
        # input touches, so the input must hold ALL of each such day. Between
        # BIND rotations only queries.log changes, and its first day is shared
        # with queries.log.0, which has not changed and so is not fresh. Without
        # the second pass that day kept only queries.log's part: measured
        # 2026-10-07, ns1 had 23,474 of 34,829 rows for 09-24, ns2 15,369 of
        # 43,525 for 08-01. So unchanged files whose span reaches a replaced
        # day contribute that day's rows (and only those) too.
        counts = [0, 0]  # rows written, lines unparsed
        spans: dict[Path, tuple[str, str] | None] = {}
        with tempfile.NamedTemporaryFile("w", suffix=".csv", newline="",
                                         delete=False) as fh:
            scratch = Path(fh.name)
            w = csv.writer(fh)
            days: set[str] = set()
            for q in fresh:
                spans[q] = _copy_rows(q, host, w, None, counts, days)
            for q in paths:
                if q in spans:
                    continue
                s = stored_span(con, host, q)
                if s is None or any(s[0] <= d <= s[1] for d in days):
                    spans[q] = _copy_rows(q, host, w, days, counts)
        bad = counts[1]
        neighbours = len(spans) - len(fresh)
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
            for q, s in spans.items():
                remember(con, host, q, s)
            con.execute("COMMIT")
        finally:
            scratch.unlink(missing_ok=True)
        written += stats[0]
        print(f"ingest-ns: {host}: {stats[0]:,} queries over {stats[1]} days "
              f"({stats[2]} .. {stats[3]}), {bad:,} unparsed, "
              f"{len(fresh)}/{len(paths)} file(s) changed, "
              f"{neighbours} neighbour(s) re-read for shared days", file=sys.stderr)

    n = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    con.execute("CHECKPOINT")
    con.close()
    size = args.db.stat().st_size / 1e9
    print(f"ingest-ns: wrote {written:,} rows; table now {n:,} rows, "
          f"{size:.2f} GB at {args.db}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
