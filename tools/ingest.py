#!/usr/bin/env python3
"""Ingest raw HoneyCow telemetry into a queryable SQLite index.

The flat `events.jsonl` (and `/var/log/ufw.log`) stay the append-only
**capture-of-record** — nothing here mutates them. This tool builds a
*derived, rebuildable* SQLite index on top so analysis can run SQL
(indexed time windows, ad-hoc joins across DNS/HTTP/UFW by source IP)
instead of re-parsing the whole log on every question. If the DB is ever
wrong, `--rebuild` (or just `rm` it) and re-ingest from the raw — cattle,
not pets.

Design notes:
  * Parse + classify are NOT duplicated here. `classify_query`,
    `classify_http` and `parse_ufw` are imported from `honeycow_digest`,
    the single source of truth the morning report and the cow-side digest
    emitter also use. This module only *stores* what they produce.
  * Idempotent. Every row carries a `rowhash` PRIMARY KEY (sha1 of the
    raw JSONL line for events, of the canonical field tuple for UFW), so
    re-ingesting the same file — or overlapping rotated files — never
    double-counts. `INSERT OR IGNORE` drops the repeats.
  * MAC is deliberately never stored: on a datacenter VPS the UFW `MAC=`
    field is the constant upstream-gateway L2 header — zero analytical
    value. `parse_ufw` doesn't even capture it.

Usage:
    tools/ingest.py --events events.jsonl --ufw ufw.log --db honeycow.db
    tools/ingest.py --events events.jsonl --db honeycow.db --dry-run
    tools/ingest.py --events events.jsonl --db honeycow.db --rebuild
    tools/ingest.py --db honeycow.db --stats
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Dual import: as a package (`tools.ingest`, how tests load it) the repo root
# is on sys.path; run as a script (`tools/ingest.py`) only `tools/` is, so
# fall back to the bare module name. Same pattern as morning_report.
try:
    from tools.honeycow_digest import classify_http, classify_query, parse_ufw
except ImportError:
    from honeycow_digest import classify_http, classify_query, parse_ufw

SCHEMA_VERSION = 2

SCHEMA = """
-- Wide by design: the JSONL is the capture-of-record, but we index every
-- scalar DNS field so ad-hoc SQL never has to fall back to grepping the raw.
-- Only edns_options_raw (per-option hex bytes) is left to the JSONL.
CREATE TABLE IF NOT EXISTS dns (
    rowhash          TEXT PRIMARY KEY,
    ts               TEXT,
    ts_epoch         REAL,
    request_id       TEXT,
    transport        TEXT,
    src_ip           TEXT,
    src_port         INTEGER,
    dst_bind         TEXT,
    raw_len          INTEGER,   -- inbound request size (amplification-in / probe size)
    event            TEXT,      -- query | query_drop
    decision         TEXT,
    handler          TEXT,
    drop_reason      TEXT,
    rate_limited     INTEGER,
    elapsed_ms       REAL,
    dns_id           INTEGER,   -- DNS transaction id (query.id), not request_id
    opcode           TEXT,
    rcode            TEXT,
    flags            INTEGER,   -- header flags bitfield (RD/AA/… for exemplars)
    qdcount          INTEGER,
    qname            TEXT,
    qtype            TEXT,
    qtype_int        INTEGER,
    qclass           TEXT,
    qclass_int       INTEGER,
    response_kind    TEXT,
    answer_count     INTEGER,
    authority_count  INTEGER,
    additional_count INTEGER,
    response_bytes   INTEGER,
    truncated        INTEGER,
    edns_version     INTEGER,   -- NULL when the query carried no EDNS OPT
    edns_payload     INTEGER,   -- advertised UDP buffer (scanner fingerprint)
    do_set           INTEGER,   -- DNSSEC-OK bit
    edns_options     TEXT,      -- JSON list of EDNS option otypes present
    family           TEXT
);
CREATE INDEX IF NOT EXISTS ix_dns_ts     ON dns(ts_epoch);
CREATE INDEX IF NOT EXISTS ix_dns_src    ON dns(src_ip);
CREATE INDEX IF NOT EXISTS ix_dns_qname  ON dns(qname);
CREATE INDEX IF NOT EXISTS ix_dns_family ON dns(family);
CREATE INDEX IF NOT EXISTS ix_dns_qtype  ON dns(qtype);

CREATE TABLE IF NOT EXISTS http (
    rowhash        TEXT PRIMARY KEY,
    ts             TEXT,
    ts_epoch       REAL,
    src_ip         TEXT,
    src_port       INTEGER,
    dst_bind       TEXT,
    client_ip      TEXT,
    forwarded_for  TEXT,
    method         TEXT,
    path           TEXT,
    host           TEXT,
    user_agent     TEXT,
    request_bytes  INTEGER,
    response_bytes INTEGER,
    elapsed_ms     REAL,
    family         TEXT
);
CREATE INDEX IF NOT EXISTS ix_http_ts     ON http(ts_epoch);
CREATE INDEX IF NOT EXISTS ix_http_src    ON http(client_ip);
CREATE INDEX IF NOT EXISTS ix_http_path   ON http(path);
CREATE INDEX IF NOT EXISTS ix_http_family ON http(family);

-- No MAC column by design (see module docstring).
CREATE TABLE IF NOT EXISTS ufw (
    rowhash  TEXT PRIMARY KEY,
    ts       TEXT,
    ts_epoch REAL,
    src      TEXT,
    dst      TEXT,
    proto    TEXT,
    dpt      INTEGER,
    verdict  TEXT
);
CREATE INDEX IF NOT EXISTS ix_ufw_ts   ON ufw(ts_epoch);
CREATE INDEX IF NOT EXISTS ix_ufw_src  ON ufw(src);
CREATE INDEX IF NOT EXISTS ix_ufw_dpt  ON ufw(dpt);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

_DNS_EVENTS = {"query", "query_drop"}


def _epoch(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None


def _int(v: object) -> int | None:
    """Coerce truthy/None to int, keeping SQLite happy (bools -> 0/1)."""
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _real(v: object) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _json(v: object) -> str | None:
    """Serialize a small list/dict field (e.g. edns_options) for storage."""
    if v is None:
        return None
    return json.dumps(v, ensure_ascii=False, sort_keys=True)


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()


def _dns_row(e: dict, raw: str) -> tuple:
    return (
        hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest(),
        e.get("ts"),
        _epoch(e.get("ts")),
        e.get("request_id"),
        e.get("transport"),
        e.get("src_ip"),
        _int(e.get("src_port")),
        e.get("dst_bind"),
        _int(e.get("raw_len")),
        e.get("event"),
        e.get("decision"),
        e.get("handler"),
        e.get("drop_reason"),
        _int(e.get("rate_limited")),
        _real(e.get("elapsed_ms")),
        _int(e.get("id")),
        e.get("opcode"),
        e.get("rcode"),
        _int(e.get("flags")),
        _int(e.get("qdcount")),
        e.get("qname"),
        e.get("qtype_name"),
        _int(e.get("qtype_int")),
        e.get("qclass_name"),
        _int(e.get("qclass_int")),
        e.get("response_kind"),
        _int(e.get("answer_count")),
        _int(e.get("authority_count")),
        _int(e.get("additional_count")),
        _int(e.get("response_bytes")),
        _int(e.get("truncated")),
        _int(e.get("edns_version")),
        _int(e.get("edns_payload")),
        _int(e.get("do_set")),
        _json(e.get("edns_options")),
        classify_query(e),
    )


def _http_row(e: dict, raw: str) -> tuple:
    return (
        hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest(),
        e.get("ts"),
        _epoch(e.get("ts")),
        e.get("src_ip"),
        _int(e.get("src_port")),
        e.get("dst_bind"),
        e.get("client_ip"),
        e.get("forwarded_for"),
        e.get("method"),
        e.get("path"),
        e.get("host"),
        e.get("user_agent"),
        _int(e.get("request_bytes")),
        _int(e.get("response_bytes")),
        _real(e.get("elapsed_ms")),
        classify_http(e.get("path") or ""),
    )


_DNS_COLS = (
    "rowhash, ts, ts_epoch, request_id, transport, src_ip, src_port, dst_bind, "
    "raw_len, event, decision, handler, drop_reason, rate_limited, elapsed_ms, "
    "dns_id, opcode, rcode, flags, qdcount, qname, qtype, qtype_int, qclass, "
    "qclass_int, response_kind, answer_count, authority_count, additional_count, "
    "response_bytes, truncated, edns_version, edns_payload, do_set, edns_options, "
    "family"
)
_HTTP_COLS = (
    "rowhash, ts, ts_epoch, src_ip, src_port, dst_bind, client_ip, "
    "forwarded_for, method, path, host, user_agent, request_bytes, "
    "response_bytes, elapsed_ms, family"
)
_UFW_COLS = "rowhash, ts, ts_epoch, src, dst, proto, dpt, verdict"


def _placeholders(cols: str) -> str:
    return ", ".join("?" for _ in cols.split(","))


def ingest_events(
    conn: sqlite3.Connection,
    path: Path,
    since: datetime | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Stream events.jsonl into the dns/http tables.

    Returns counts: dns/http seen (in window) and dns/http newly inserted.
    In dry-run mode nothing is written; "new" is computed against the
    rowhashes already present so the preview is honest.
    """
    dns_seen = http_seen = dns_new = http_new = 0
    existing = _existing_rowhashes(conn, ("dns", "http")) if dry_run else None
    dns_rows: list[tuple] = []
    http_rows: list[tuple] = []

    def flush() -> None:
        nonlocal dns_new, http_new
        if not dry_run and dns_rows:
            dns_new += _insert(conn, "dns", _DNS_COLS, dns_rows)
            dns_rows.clear()
        if not dry_run and http_rows:
            http_new += _insert(conn, "http", _HTTP_COLS, http_rows)
            http_rows.clear()

    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            raw = line.strip()
            if not raw:
                continue
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            if since is not None:
                ep = _epoch(e.get("ts"))
                if ep is None or ep < since.timestamp():
                    continue
            event = e.get("event")
            if event in _DNS_EVENTS:
                dns_seen += 1
                row = _dns_row(e, raw)
                if dry_run:
                    if row[0] not in existing["dns"]:
                        existing["dns"].add(row[0])
                        dns_new += 1
                else:
                    dns_rows.append(row)
                    if len(dns_rows) >= 5000:
                        flush()
            elif event == "http_closer":
                http_seen += 1
                row = _http_row(e, raw)
                if dry_run:
                    if row[0] not in existing["http"]:
                        existing["http"].add(row[0])
                        http_new += 1
                else:
                    http_rows.append(row)
                    if len(http_rows) >= 5000:
                        flush()
    flush()
    if not dry_run:
        conn.commit()
    return {
        "dns_seen": dns_seen, "dns_new": dns_new,
        "http_seen": http_seen, "http_new": http_new,
    }


def _ufw_rowhash(u: dict) -> str:
    ts = u.get("ts")
    key = "|".join(str(x) for x in (
        ts.isoformat() if isinstance(ts, datetime) else ts,
        u.get("src"), u.get("dst"), u.get("proto"),
        u.get("dpt"), u.get("verdict"),
    ))
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()


def ingest_ufw(
    conn: sqlite3.Connection,
    path: Path,
    since: datetime | None = None,
    *,
    dry_run: bool = False,
) -> dict[str, int]:
    """Parse ufw.log (reusing honeycow_digest.parse_ufw) into the ufw table."""
    floor = since if since is not None else datetime.min.replace(tzinfo=UTC)
    parsed = parse_ufw(path, floor)
    rows = []
    for u in parsed:
        ts = u.get("ts")
        ts_iso = ts.isoformat() if isinstance(ts, datetime) else ts
        rows.append((
            _ufw_rowhash(u), ts_iso,
            ts.timestamp() if isinstance(ts, datetime) else _epoch(ts_iso),
            u.get("src"), u.get("dst"), u.get("proto"),
            _int(u.get("dpt")), u.get("verdict"),
        ))
    if dry_run:
        existing = _existing_rowhashes(conn, ("ufw",))["ufw"]
        new = sum(1 for r in rows if r[0] not in existing)
        return {"ufw_seen": len(rows), "ufw_new": new}
    new = _insert(conn, "ufw", _UFW_COLS, rows)
    conn.commit()
    return {"ufw_seen": len(rows), "ufw_new": new}


def _insert(
    conn: sqlite3.Connection, table: str, cols: str, rows: list[tuple],
) -> int:
    """INSERT OR IGNORE a batch; return the number actually inserted."""
    if not rows:
        return 0
    before = conn.total_changes
    conn.executemany(
        f"INSERT OR IGNORE INTO {table} ({cols}) VALUES ({_placeholders(cols)})",
        rows,
    )
    return conn.total_changes - before


def _existing_rowhashes(
    conn: sqlite3.Connection, tables: tuple[str, ...],
) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for t in tables:
        try:
            out[t] = {r[0] for r in conn.execute(f"SELECT rowhash FROM {t}")}
        except sqlite3.OperationalError:
            out[t] = set()  # table not created yet
    return out


def table_stats(conn: sqlite3.Connection) -> dict[str, dict]:
    stats: dict[str, dict] = {}
    for t in ("dns", "http", "ufw"):
        try:
            row = conn.execute(
                f"SELECT COUNT(*) n, MIN(ts) lo, MAX(ts) hi FROM {t}",
            ).fetchone()
        except sqlite3.OperationalError:
            stats[t] = {"rows": 0, "first": None, "last": None}
            continue
        stats[t] = {"rows": row["n"], "first": row["lo"], "last": row["hi"]}
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest HoneyCow events.jsonl + ufw.log into a SQLite index.",
    )
    ap.add_argument("--db", required=True, type=Path,
                    help="SQLite database path (created if absent)")
    ap.add_argument("--events", type=Path, default=None,
                    help="path to events.jsonl")
    ap.add_argument("--ufw", type=Path, default=None,
                    help="path to a (concatenated) ufw.log")
    ap.add_argument("--hours", type=float, default=None,
                    help="only ingest the last N hours (default: all)")
    ap.add_argument("--rebuild", action="store_true",
                    help="delete the DB first and ingest from scratch")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be inserted without writing")
    ap.add_argument("--stats", action="store_true",
                    help="print table row counts + time span and exit")
    args = ap.parse_args(argv)

    since = None
    if args.hours is not None:
        since = datetime.now(tz=UTC) - timedelta(hours=args.hours)

    if args.rebuild and not args.dry_run and args.db.exists():
        args.db.unlink()

    conn = connect(args.db)
    try:
        if args.stats:
            for t, s in table_stats(conn).items():
                print(f"{t:5}  rows={s['rows']:<10} "
                      f"first={s['first']}  last={s['last']}")
            return 0

        if not args.dry_run:
            init_schema(conn)

        if not args.events and not args.ufw:
            ap.error("nothing to do: pass --events and/or --ufw (or --stats)")

        totals: dict[str, int] = {}
        if args.events:
            totals.update(ingest_events(conn, args.events, since,
                                        dry_run=args.dry_run))
        if args.ufw:
            totals.update(ingest_ufw(conn, args.ufw, since,
                                     dry_run=args.dry_run))

        tag = "[dry-run] would insert" if args.dry_run else "inserted"
        parts = []
        for kind in ("dns", "http", "ufw"):
            seen = totals.get(f"{kind}_seen")
            if seen is None:
                continue
            parts.append(f"{kind}: {tag} {totals[f'{kind}_new']}/{seen} seen")
        print(f"{args.db}: " + "; ".join(parts), file=sys.stderr)
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
