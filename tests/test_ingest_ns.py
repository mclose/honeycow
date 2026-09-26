"""tools/ingest_ns.py — the BIND parser and the idempotency guarantee.

These pin the *contract*: which line shapes are understood, what is
deliberately preserved (0x20 casing) and dropped (response lines), and that
re-ingesting overlapping pulls cannot double-count. The sample lines are real,
copied from ns1/ns2/ns3.
"""

from __future__ import annotations

import pytest

import tools.ingest_ns as ing

FILE_LINE = (
    "24-Sep-2026 07:40:56.791 queries: info: client @0x77cfd5794c00 "
    "76.13.112.47#48677 (deflationhollow.net): query: deflationhollow.net "
    "IN SOA + (216.128.180.194)"
)
SYSLOG_LINE = (
    "2026-07-26T00:00:17.597399+00:00 bind9-dallas-dh-ns1 named[63297]: "
    "client @0x749d36360c00 2604:a880:800:14:0:2:8b6f:3000#62713 "
    "(deflationhollow.net): query: deflationhollow.net IN A -E(0)D (1.2.3.4)"
)
ZERO_X20_LINE = (
    "13-Mar-2026 03:11:44.539 queries: info: client @0x78236b177c00 "
    "2a01:4ff:ef::add:1a#42794 (NS2.dEfLATiONHoLlOw.Net): query: "
    "NS2.dEfLATiONHoLlOw.Net IN A -E(0)DC (46.224.1.1)"
)
RESPONSE_LINE = (
    "21-Sep-2026 23:37:38.921 responses: info: client @0x7b61bf23bc00 "
    "167.71.83.144#33513 (caddy.example.net): response: caddy.example.net IN A"
)


def test_the_current_file_channel_parses():
    ts, day, src, asked, qname, qclass, qtype, flags = ing.parse_line(FILE_LINE)
    assert (day, src, qname, qclass, qtype) == (
        "2026-09-24", "76.13.112.47", "deflationhollow.net", "IN", "SOA")
    assert ts == "2026-09-24T07:40:56.791"
    assert flags == "+"


def test_the_pre_true_up_syslog_channel_parses():
    """ns1/ns2 logged through syslog until 2026-08-01. Same body, different
    timestamp — worth ~4 extra weeks of history for one regex."""
    ts, day, src, _, qname, _, qtype, _ = ing.parse_line(SYSLOG_LINE)
    assert day == "2026-07-26" and ts == "2026-07-26T00:00:17.597"
    assert src == "2604:a880:800:14:0:2:8b6f:3000", "IPv6 sources must survive"
    assert qname == "deflationhollow.net" and qtype == "A"


def test_0x20_casing_is_preserved_alongside_the_normalised_name():
    """Resolvers randomise capitalisation as an off-path spoofing defence, so
    the asked-for casing is signal about who is asking — not noise."""
    _, _, _, asked, qname, _, _, _ = ing.parse_line(ZERO_X20_LINE)
    assert asked == "NS2.dEfLATiONHoLlOw.Net", "original casing must survive"
    assert qname == "ns2.deflationhollow.net", "and a normalised form must exist"


def test_response_lines_are_not_queries():
    """queries.log carries response/xfer/notify traffic too. Counting a
    response as a query would inflate every volume number on the page."""
    assert " query: " not in RESPONSE_LINE


@pytest.mark.parametrize("junk", [
    "", "\n", "not a log line at all",
    "24-Sep-2026 07:40:56.791 queries: info: truncated",
    "99-Xxx-2026 07:40:56.791 queries: info: client @0x1 1.2.3.4#1 (a): query: a IN A",
])
def test_unparseable_lines_return_none_rather_than_raising(junk):
    """A rotated file can be cut mid-line. One bad line must not end an ingest."""
    assert ing.parse_line(junk) is None


def _write_log(tmp_path, host, lines):
    d = tmp_path / host
    d.mkdir(parents=True, exist_ok=True)
    (d / "queries.log").write_text("\n".join(lines) + "\n")
    return tmp_path


def test_reingesting_the_same_logs_does_not_double_count(tmp_path):
    """BIND rotates rather than appending, so pulls overlap by construction.
    `ingest.py` gets this from a per-row hash; here it comes from replacing
    each (host, day) partition whole — measured 6x cheaper at this row count."""
    duckdb = pytest.importorskip("duckdb")
    logs = _write_log(tmp_path / "logs", "ns1", [FILE_LINE, ZERO_X20_LINE])
    db = tmp_path / "ns.duckdb"
    argv = ["--logs", str(logs), "--db", str(db), "--hosts", "ns1"]

    assert ing.main(argv) == 0
    con = duckdb.connect(str(db), read_only=True)
    first = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    con.close()
    assert first == 2

    assert ing.main(argv) == 0
    con = duckdb.connect(str(db), read_only=True)
    again = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    con.close()
    assert again == first, "a second ingest of identical input must be a no-op"


def test_a_new_day_adds_without_disturbing_the_old(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    logs = _write_log(tmp_path / "logs", "ns1", [ZERO_X20_LINE])
    db = tmp_path / "ns.duckdb"
    argv = ["--logs", str(logs), "--db", str(db), "--hosts", "ns1"]
    assert ing.main(argv) == 0

    _write_log(tmp_path / "logs", "ns1", [ZERO_X20_LINE, FILE_LINE])
    assert ing.main(argv) == 0
    con = duckdb.connect(str(db), read_only=True)
    days = {r[0] for r in con.execute("SELECT DISTINCT day FROM ns_queries").fetchall()}
    n = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    con.close()
    assert days == {"2026-03-13", "2026-09-24"} and n == 2


def test_hosts_are_kept_apart(tmp_path):
    """ns1/ns2/ns3 are separate vantage points; merging them would destroy the
    only thing three sensors buy."""
    duckdb = pytest.importorskip("duckdb")
    root = tmp_path / "logs"
    _write_log(root, "ns1", [FILE_LINE])
    _write_log(root, "ns3", [FILE_LINE])
    db = tmp_path / "ns.duckdb"
    assert ing.main(["--logs", str(root), "--db", str(db),
                     "--hosts", "ns1 ns3"]) == 0
    con = duckdb.connect(str(db), read_only=True)
    rows = dict(con.execute("SELECT host, COUNT(*) FROM ns_queries GROUP BY host").fetchall())
    con.close()
    assert rows == {"ns1": 1, "ns3": 1}


def test_unchanged_files_are_not_reparsed(tmp_path):
    """Without this every 4-hourly run re-parses the whole 2.5 GB corpus."""
    duckdb = pytest.importorskip("duckdb")
    logs = _write_log(tmp_path / "logs", "ns1", [FILE_LINE])
    db = tmp_path / "ns.duckdb"
    argv = ["--logs", str(logs), "--db", str(db), "--hosts", "ns1"]
    assert ing.main(argv) == 0

    con = duckdb.connect(str(db), read_only=True)
    fp = con.execute("SELECT fingerprint FROM ns_files").fetchall()
    con.close()
    assert len(fp) == 1, "the ingested file must be remembered"

    # A second run sees nothing changed and must leave the table alone.
    assert ing.main(argv) == 0
    con = duckdb.connect(str(db), read_only=True)
    assert con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0] == 1
    con.close()


def test_a_changed_file_is_reread_and_its_days_replaced(tmp_path):
    """The live queries.log grows between runs; its day must not double."""
    duckdb = pytest.importorskip("duckdb")
    root = tmp_path / "logs"
    _write_log(root, "ns1", [FILE_LINE])
    db = tmp_path / "ns.duckdb"
    argv = ["--logs", str(root), "--db", str(db), "--hosts", "ns1"]
    assert ing.main(argv) == 0

    # Same day, one more query appended.
    second = FILE_LINE.replace("76.13.112.47", "8.8.8.8")
    _write_log(root, "ns1", [FILE_LINE, second])
    assert ing.main(argv) == 0
    con = duckdb.connect(str(db), read_only=True)
    n = con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0]
    ips = {r[0] for r in con.execute("SELECT DISTINCT src_ip FROM ns_queries").fetchall()}
    con.close()
    assert n == 2, "the day is replaced whole, not appended to"
    assert ips == {"76.13.112.47", "8.8.8.8"}


def test_force_reingests_an_unchanged_file_without_duplicating(tmp_path):
    duckdb = pytest.importorskip("duckdb")
    logs = _write_log(tmp_path / "logs", "ns1", [FILE_LINE, ZERO_X20_LINE])
    db = tmp_path / "ns.duckdb"
    argv = ["--logs", str(logs), "--db", str(db), "--hosts", "ns1"]
    assert ing.main(argv) == 0
    assert ing.main(argv + ["--force"]) == 0
    con = duckdb.connect(str(db), read_only=True)
    assert con.execute("SELECT COUNT(*) FROM ns_queries").fetchone()[0] == 2
    con.close()
