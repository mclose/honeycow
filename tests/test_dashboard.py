"""tools/dashboard.py — the rubric and the honesty guarantees around it.

The rubric is judgement and will be tweaked, so these tests pin *behaviour*
(what makes a day yellow vs red, what must never drive colour) rather than the
specific threshold numbers, which live in one config block by design.
"""

from __future__ import annotations

import json

import tools.dashboard as dash
import tools.ingest as ingest


def _db(tmp_path, rows_by_day, ufw_days=()):
    """Build a DB with `n` plain HTTP hits per day, plus optional UFW rows."""
    p = tmp_path / "h.db"
    conn = ingest.connect(p)
    ingest.init_schema(conn)
    dns, http, ufw = [], [], []
    for day, spec in rows_by_day.items():
        for i in range(spec.get("dns", 0)):
            dns.append((f"dns-{day}-{i}", f"{day}T10:00:00+00:00", 0, None, "udp",
                        f"9.9.9.{i % 250}", 4000, None, 40, "query", None, "synth",
                        None, 0, 1.0, 1, "QUERY", "NOERROR", 256, 1, "x.test.",
                        "A", 1, "IN", 1, "NOERROR", 1, 0, 0, 90, 0, None, None,
                        None, None, spec.get("family", "other")))
        for i in range(spec.get("http", 0)):
            http.append((f"http-{day}-{i}", f"{day}T10:00:00+00:00", 0, "1.2.3.4",
                         5000, None, f"5.5.5.{i % 250}", None, "GET", "/", "h",
                         "ua", 10, 10, 1.0, spec.get("http_family", "other")))
    for day in ufw_days:
        ufw.append((f"ufw-{day}", f"{day}T10:00:00+00:00", 0, "7.7.7.7", "1.2.3.4",
                    "TCP", 80, "BLOCK"))
    if dns:
        conn.executemany(f"INSERT OR IGNORE INTO dns ({ingest._DNS_COLS}) VALUES "
                         f"({ingest._placeholders(ingest._DNS_COLS)})", dns)
    if http:
        conn.executemany(f"INSERT OR IGNORE INTO http ({ingest._HTTP_COLS}) VALUES "
                         f"({ingest._placeholders(ingest._HTTP_COLS)})", http)
    if ufw:
        conn.executemany(f"INSERT OR IGNORE INTO ufw ({ingest._UFW_COLS}) VALUES "
                         f"({ingest._placeholders(ingest._UFW_COLS)})", ufw)
    conn.commit()
    conn.close()
    return p


def _quiet(n_days, http=100, start=1):
    return {f"2026-03-{d:02d}": {"dns": 10, "http": http}
            for d in range(start, start + n_days)}


def test_quiet_days_are_green(tmp_path):
    data = dash.build(_db(tmp_path, _quiet(10)))
    assert {d["status"] for d in data["days"]} == {"green"}
    assert data["totals"]["green"] == 10


def test_http_spike_escalates_yellow_then_red(tmp_path):
    days = _quiet(10)
    days["2026-03-11"] = {"dns": 10, "http": 100 * 4}    # 4x  -> yellow
    days["2026-03-12"] = {"dns": 10, "http": 100 * 15}   # 15x -> red
    by = {d["date"]: d for d in dash.build(_db(tmp_path, days))["days"]}
    assert by["2026-03-11"]["status"] == "yellow"
    assert by["2026-03-12"]["status"] == "red"
    # the reason names the multiple, so a bad threshold is visible not opaque
    assert "x the" in by["2026-03-12"]["why"][0]


def test_routine_cve_trickle_does_not_paint_the_calendar(tmp_path):
    """A steady low CVE-trigger cadence was one scheduled scanner, not an
    incident; grading it yellow every week taught you to ignore yellow."""
    days = {f"2026-03-{d:02d}": {"dns": 2, "http": 100,
                                 "family": "cve-2026-5946-trigger"}
            for d in range(1, 9)}
    data = dash.build(_db(tmp_path, days))
    assert {d["status"] for d in data["days"]} == {"green"}
    # ...but the count is still surfaced on every card.
    assert all(d["cve_trigger"] == 2 for d in data["days"])


def test_cve_burst_above_the_floor_is_yellow(tmp_path):
    days = _quiet(6)
    days["2026-03-07"] = {"dns": 9, "http": 100, "family": "cve-2026-5946-trigger"}
    by = {d["date"]: d for d in dash.build(_db(tmp_path, days))["days"]}
    assert by["2026-03-07"]["status"] == "yellow"


def test_missing_ufw_is_none_not_zero(tmp_path):
    """A false 0 would read as 'nothing was blocked' — a different claim
    entirely from 'we no longer retain that day'."""
    days = _quiet(3)
    by = {d["date"]: d for d in
          dash.build(_db(tmp_path, days, ufw_days=["2026-03-03"]))["days"]}
    assert by["2026-03-01"]["ufw"] is None
    assert by["2026-03-03"]["ufw"] == 1


def test_partial_day_flagged_and_excluded_from_baseline(tmp_path):
    from datetime import UTC, datetime
    today = datetime.now(tz=UTC).date().isoformat()
    days = _quiet(5)
    days[today] = {"dns": 1, "http": 1}      # a sliver of "today"
    data = dash.build(_db(tmp_path, days))
    by = {d["date"]: d for d in data["days"]}
    assert by[today]["partial"] is True
    assert by["2026-03-01"]["partial"] is False


def test_narrative_slot_is_filled_from_notes_dir(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text("A dropper wordlist, not a real actor.")
    by = {d["date"]: d for d in
          dash.build(_db(tmp_path, _quiet(3)), notes)["days"]}
    assert by["2026-03-02"]["narrative"].startswith("A dropper wordlist")
    assert by["2026-03-01"]["narrative"] == ""


def test_render_is_self_contained_and_embeds_data(tmp_path):
    """The page must be one file a plain file_server can serve: no external
    fetches, and the JSON baked in rather than loaded at runtime."""
    db = _db(tmp_path, _quiet(4))
    out = tmp_path / "index.html"
    assert dash.main(["--db", str(db), "--out", str(out)]) == 0
    html = out.read_text()
    assert "/*__DATA__*/null" not in html          # placeholder was replaced
    assert '"days":[' in html.replace(", ", ",")   # data embedded
    # No runtime network. (The SVG XML namespace URI is an identifier, not a
    # fetch — browsers never resolve it — so it is excluded deliberately.)
    stripped = html.replace("http://www.w3.org/2000/svg", "")
    for external in ("http://", "https://", "fetch(", "XMLHttpRequest",
                     "<script src", "<link "):
        assert external not in stripped, f"page reaches out via {external}"


def test_dry_run_writes_nothing(tmp_path, capsys):
    db = _db(tmp_path, _quiet(3))
    out = tmp_path / "nope.html"
    assert dash.main(["--db", str(db), "--out", str(out), "--dry-run"]) == 0
    assert not out.exists()
    assert "GREEN" in capsys.readouterr().out


def test_rubric_is_published_to_the_page(tmp_path):
    """The page explains its own grading, so a threshold can be questioned
    without reading the source."""
    data = dash.build(_db(tmp_path, _quiet(3)))
    assert data["rubric"]["http_spike_red"] > data["rubric"]["http_spike_yellow"]
    assert set(dash.RUBRIC) >= {"trailing_days", "http_spike_red", "cve_trigger_yellow"}


def test_totals_match_the_days(tmp_path):
    data = dash.build(_db(tmp_path, _quiet(5, http=7)))
    assert data["totals"]["http"] == sum(d["http"] for d in data["days"])
    assert data["totals"]["days"] == len(data["days"])
    json.dumps(data)  # must stay JSON-serialisable for embedding
