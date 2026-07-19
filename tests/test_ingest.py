"""tools/ingest.py — SQLite index over the raw JSONL/UFW capture-of-record.

Pins the properties that make the DB a *safe derived index*: it stores what
the shared classifier produces, it is idempotent (re-ingesting overlapping
files never double-counts), --dry-run touches nothing, and MAC is never
stored.
"""

from __future__ import annotations

import sqlite3

import tools.ingest as ingest

# --- fixtures ---------------------------------------------------------------

def _events_file(tmp_path):
    """A small events.jsonl covering a query, a drop, and an http_closer."""
    p = tmp_path / "events.jsonl"
    lines = [
        '{"event":"query","ts":"2026-07-18T10:00:00+00:00","src_ip":"45.33.12.1",'
        '"src_port":40000,"transport":"udp","qname":"x.example.","qtype_name":"A",'
        '"qclass_name":"IN","opcode":"QUERY","response_kind":"NOERROR",'
        '"handler":"synth_a","response_bytes":120,"truncated":false}',
        # CHAOS banner probe -> chaos-banner family
        '{"event":"query","ts":"2026-07-18T10:00:01+00:00","src_ip":"45.33.12.1",'
        '"src_port":40001,"transport":"udp","qname":"version.bind.",'
        '"qtype_name":"TXT","qclass_name":"CH","opcode":"QUERY",'
        '"response_kind":"NOERROR","handler":"synth_txt_ch"}',
        # a drop
        '{"event":"query_drop","ts":"2026-07-18T10:00:02+00:00","src_ip":"9.9.9.9",'
        '"src_port":53,"transport":"udp","drop_reason":"DROPPED_QR"}',
        # http closer hitting the dotenv family
        '{"event":"http_closer","ts":"2026-07-18T10:00:03+00:00",'
        '"src_ip":"45.33.12.9","client_ip":"45.33.12.9","method":"GET",'
        '"path":"/.env","host":"142.93.181.53","user_agent":"curl/8",'
        '"request_bytes":80,"response_bytes":300}',
        "",  # blank line — must be skipped
        "{not valid json",  # garbage — must be skipped
    ]
    p.write_text("\n".join(lines) + "\n")
    return p


def _ufw_file(tmp_path):
    """A ufw.log with a MAC= field present, to prove MAC is dropped."""
    p = tmp_path / "ufw.log"
    p.write_text(
        "2026-07-18T10:05:00.111111+00:00 host kernel: [UFW BLOCK] "
        "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 "
        "SRC=5.61.209.43 DST=142.93.181.53 LEN=44 PROTO=TCP SPT=51000 DPT=81\n"
        "2026-07-18T10:05:01.222222+00:00 host kernel: [UFW BLOCK] "
        "IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:08:00 "
        "SRC=5.61.209.43 DST=142.93.181.53 LEN=44 PROTO=TCP SPT=51001 DPT=82\n"
    )
    return p


# --- schema + basic ingest --------------------------------------------------

def test_ingest_populates_tables_and_families(tmp_path):
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)

    ev = ingest.ingest_events(conn, _events_file(tmp_path))
    assert ev["dns_seen"] == 3  # two queries + one drop
    assert ev["dns_new"] == 3
    assert ev["http_seen"] == 1
    assert ev["http_new"] == 1

    uf = ingest.ingest_ufw(conn, _ufw_file(tmp_path))
    assert uf["ufw_seen"] == 2
    assert uf["ufw_new"] == 2

    # families come from the shared classifier, not a local copy.
    fams = dict(conn.execute("SELECT family, COUNT(*) FROM dns GROUP BY family"))
    assert fams.get("other") == 1          # x.example. A
    assert fams.get("chaos-banner") == 1   # version.bind. CH TXT
    http_fam = conn.execute("SELECT family FROM http").fetchone()[0]
    assert http_fam == "env-harvest"

    # drop row is retained with its reason for later triage.
    drop = conn.execute(
        "SELECT drop_reason FROM dns WHERE event='query_drop'"
    ).fetchone()
    assert drop["drop_reason"] == "DROPPED_QR"


def test_mac_is_never_stored(tmp_path):
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    ingest.ingest_ufw(conn, _ufw_file(tmp_path))
    cols = {r[1] for r in conn.execute("PRAGMA table_info(ufw)")}
    assert "mac" not in {c.lower() for c in cols}
    # and the port survived parsing correctly
    dpts = sorted(r[0] for r in conn.execute("SELECT dpt FROM ufw"))
    assert dpts == [81, 82]


# --- idempotency ------------------------------------------------------------

def test_reingest_is_idempotent(tmp_path):
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    events = _events_file(tmp_path)
    ufw = _ufw_file(tmp_path)

    ingest.ingest_events(conn, events)
    ingest.ingest_ufw(conn, ufw)
    # Second pass over the identical files must insert nothing new.
    ev2 = ingest.ingest_events(conn, events)
    uf2 = ingest.ingest_ufw(conn, ufw)
    assert ev2["dns_new"] == 0
    assert ev2["http_new"] == 0
    assert uf2["ufw_new"] == 0

    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM http").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM ufw").fetchone()[0] == 2


# --- dry-run + windowing ----------------------------------------------------

def test_dry_run_writes_nothing(tmp_path):
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    ev = ingest.ingest_events(conn, _events_file(tmp_path), dry_run=True)
    # reports what WOULD be inserted...
    assert ev["dns_new"] == 3
    assert ev["http_new"] == 1
    # ...but the tables stay empty.
    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM http").fetchone()[0] == 0


def test_hours_window_filters_old_events(tmp_path):
    from datetime import UTC, datetime, timedelta

    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    # cutoff far in the future relative to the 2026-07-18 fixtures -> all excluded
    future = datetime.now(tz=UTC) + timedelta(days=3650)
    ev = ingest.ingest_events(conn, _events_file(tmp_path), since=future)
    assert ev["dns_seen"] == 0
    assert ev["http_seen"] == 0


# --- CLI smoke --------------------------------------------------------------

def test_main_rebuild_and_stats(tmp_path, capsys):
    db = tmp_path / "h.db"
    events = _events_file(tmp_path)
    ufw = _ufw_file(tmp_path)
    rc = ingest.main(["--db", str(db), "--events", str(events),
                      "--ufw", str(ufw), "--rebuild"])
    assert rc == 0
    assert db.exists()

    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM dns").fetchone()[0] == 3
    ver = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'"
    ).fetchone()[0]
    assert ver == str(ingest.SCHEMA_VERSION)
    conn.close()

    # --stats prints a per-table summary and exits 0.
    capsys.readouterr()
    rc = ingest.main(["--db", str(db), "--stats"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dns" in out and "http" in out and "ufw" in out
