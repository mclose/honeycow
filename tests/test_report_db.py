"""morning_report --db must render identically to --events.

The SQLite index (tools/ingest.py) is a derived view of the raw JSONL; the
report must not care which one it read. This is the losslessness gate for the
dimensions the index keeps — the same style of check the herd digest has.

Fixtures here are duplicate-free, so equality is EXACT (on real data the only
difference is the DB's dedup of byte-identical UFW log lines, which is a
correctness improvement, not a regression).
"""

from __future__ import annotations

from datetime import UTC, datetime

import tools.ingest as ingest
import tools.morning_report as report


def _events_file(tmp_path):
    p = tmp_path / "events.jsonl"
    lines = [
        # plain external A query
        '{"event":"query","ts":"2026-07-18T10:00:00+00:00","src_ip":"45.33.12.1",'
        '"src_port":40000,"transport":"udp","qname":"x.example.","qtype_name":"A",'
        '"qclass_name":"IN","opcode":"QUERY","response_kind":"NOERROR",'
        '"handler":"synth_a","flags":256}',
        # CVE-2026-5946 trigger shape (non-IN class, non-banner qname) with RD set
        # — exercises the flags round-trip in the CVE-exemplar section.
        '{"event":"query","ts":"2026-07-18T10:00:01+00:00","src_ip":"45.33.12.2",'
        '"src_port":40001,"transport":"udp","qname":"honeycow.net.",'
        '"qtype_name":"A","qclass_name":"CH","opcode":"QUERY",'
        '"response_kind":"REFUSED","handler":"synth","flags":256}',
        # inbound QR=1 drop
        '{"event":"query_drop","ts":"2026-07-18T10:00:02+00:00","src_ip":"9.9.9.9",'
        '"src_port":53,"transport":"udp","drop_reason":"DROPPED_QR","flags":33792}',
        # http closer
        '{"event":"http_closer","ts":"2026-07-18T10:00:03+00:00",'
        '"src_ip":"45.33.12.9","client_ip":"45.33.12.9","method":"GET",'
        '"path":"/.env","host":"h","user_agent":"curl"}',
    ]
    p.write_text("\n".join(lines) + "\n")
    return p


def _ufw_file(tmp_path):
    p = tmp_path / "ufw.log"
    p.write_text(
        "2026-07-18T10:05:00.111111+00:00 host kernel: [UFW BLOCK] "
        "SRC=5.61.209.43 DST=1.2.3.4 PROTO=TCP SPT=5 DPT=80\n"
        "2026-07-18T10:05:01.222222+00:00 host kernel: [UFW BLOCK] "
        "SRC=5.61.209.43 DST=1.2.3.4 PROTO=TCP SPT=6 DPT=443\n"
        "2026-07-18T10:05:02.333333+00:00 host kernel: [UFW BLOCK] "
        "SRC=9.9.9.9 DST=1.2.3.4 PROTO=UDP SPT=7 DPT=53\n"
    )
    return p


def _render_to_str(capsys, events, ufw):
    capsys.readouterr()  # clear
    report.render(events, ufw, None, our_nets=[], research_nets=[])
    return capsys.readouterr().out


def test_db_report_matches_raw_report(tmp_path, capsys):
    events_f = _events_file(tmp_path)
    ufw_f = _ufw_file(tmp_path)
    since = datetime(2000, 1, 1, tzinfo=UTC)  # everything in window

    # raw path
    events_raw = report.load_events(events_f, since)
    ufw_raw = report.parse_ufw(ufw_f, since)
    raw_out = _render_to_str(capsys, events_raw, ufw_raw)

    # index path
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    ingest.ingest_events(conn, events_f)
    ingest.ingest_ufw(conn, ufw_f)
    conn.close()
    events_db, ufw_db = report.load_from_db(db, since)
    db_out = _render_to_str(capsys, events_db, ufw_db)

    assert db_out == raw_out
    # sanity: the fixtures actually produced content, not two empty reports
    assert "totals" in raw_out and "CVE-2026-5946" in raw_out


def test_db_loader_respects_window(tmp_path):
    events_f = _events_file(tmp_path)
    ufw_f = _ufw_file(tmp_path)
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    ingest.ingest_events(conn, events_f)
    ingest.ingest_ufw(conn, ufw_f)
    conn.close()

    # a cutoff after every fixture timestamp -> nothing returned
    future = datetime(2030, 1, 1, tzinfo=UTC)
    events, ufw = report.load_from_db(db, future)
    assert events == []
    assert ufw == []


def test_db_dpt_is_string_like_parse_ufw(tmp_path):
    """render() sorts/format DPT as text; the loader must mirror parse_ufw."""
    ufw_f = _ufw_file(tmp_path)
    db = tmp_path / "h.db"
    conn = ingest.connect(db)
    ingest.init_schema(conn)
    ingest.ingest_ufw(conn, ufw_f)
    conn.close()
    _events, ufw = report.load_from_db(db, datetime(2000, 1, 1, tzinfo=UTC))
    assert all(isinstance(u["dpt"], str) for u in ufw)
