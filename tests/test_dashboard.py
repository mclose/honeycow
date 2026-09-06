"""tools/dashboard.py — the rubric and the honesty guarantees around it.

The rubric is judgement and will be tweaked, so these tests pin *behaviour*
(what makes a day yellow vs red, what must never drive colour) rather than the
specific threshold numbers, which live in one config block by design.
"""

from __future__ import annotations

import json
import re

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
        # A reflection-shaped burst: many queries sharing ONE (src_ip, txid,
        # src_port) tuple. Spread over `span` seconds so span_s is non-zero.
        for b_i, b in enumerate(spec.get("bursts", [])):
            for i in range(b["n"]):
                sec = int(i * b.get("span", 10) / max(b["n"] - 1, 1))
                dns.append((f"burst-{day}-{b_i}-{i}",
                            f"{day}T11:00:{sec:02d}+00:00", 0, None, "udp",
                            b["src_ip"], b.get("src_port", 29852), None, 38, "query",
                            b.get("decision", "respond"), "synth_txt", None, 0, 1.0,
                            b.get("dns_id", 32058), "QUERY", "NOERROR", 256, 1,
                            "cam.ac.uk.", "TXT", 16, "IN", 1, "NOERROR", 1, 0, 0,
                            293, 0, None, None, None, None, "other"))

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
    assert by["2026-03-02"]["narrative"]["text"].startswith("A dropper wordlist")
    assert by["2026-03-01"]["narrative"] is None


def test_bare_note_is_attributed_to_a_human(tmp_path):
    """A note with no frontmatter predates the annotator — a person wrote it.
    Getting this backwards would label hand-written analysis as machine output."""
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text("Checked by hand.")
    by = {d["date"]: d for d in dash.build(_db(tmp_path, _quiet(3)), notes)["days"]}
    assert by["2026-03-02"]["narrative"]["source"] == "human"
    assert by["2026-03-02"]["narrative"]["model"] == ""


def test_model_note_carries_its_provenance(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text(
        "---\nsource: model\nmodel: claude-opus-5\n"
        "generated: 2026-03-03T00:00:00+00:00\nstatus: yellow\n---\n"
        "A measurement study, not recon.\n")
    by = {d["date"]: d for d in dash.build(_db(tmp_path, _quiet(3)), notes)["days"]}
    n = by["2026-03-02"]["narrative"]
    assert n["source"] == "model"
    assert n["model"] == "claude-opus-5"
    assert n["generated"].startswith("2026-03-03")
    # The frontmatter must not bleed into the rendered prose.
    assert n["text"] == "A measurement study, not recon."
    assert "source:" not in n["text"]


def test_missing_notes_are_reported_even_when_annotator_never_ran(tmp_path):
    """The health signal must not depend on the annotator writing anything —
    a dead annotator is exactly the case the operator needs to see."""
    days = _quiet(3)
    days["2026-03-02"] = {"dns": 9, "http": 4000}  # loud enough to grade non-green
    data = dash.build(_db(tmp_path, days), tmp_path / "notes")
    graded = {d["date"] for d in data["days"] if d["status"] != "green" and not d["partial"]}
    assert graded, "fixture must produce at least one non-green settled day"
    assert set(data["annotator"]["missing"]) == graded
    assert data["annotator"]["last_run"] == ""


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
    # A <link> carrying a data: URI is inert for the same reason: the bytes are
    # already in this file and nothing is resolved. Only that shape is exempt --
    # a <link> pointing at a real URL still trips the check below.
    stripped = re.sub(r'<link\b[^>]*href="data:[^"]*"[^>]*>', "", stripped)
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


# --- reflection-shaped bursts (QR=0 side) -----------------------------------
#
# `qr_oversized_nonresearch` only sees QR=1 packets arriving. These pin the
# other half: the QR=0 flood that makes honeycow the reflector. A real resolver
# picks a fresh transaction id and source port per query, so many queries
# sharing one tuple means the named source is a spoofed victim.

def _burst_days(day, **burst):
    """Ten quiet days, with one carrying a frozen-tuple burst.

    The DNS baseline is deliberately high (500/day): a burst also *adds*
    queries, and against a 10/day baseline it would trip the unrelated DNS
    volume rule and mask what these tests are actually pinning.
    """
    days = {f"2026-03-{d:02d}": {"dns": 500, "http": 100} for d in range(1, 11)}
    days[day] = {**days[day],
                 "bursts": [{"src_ip": "163.5.59.20", "n": 25, **burst}]}
    return days


def test_frozen_txid_and_port_burst_is_red(tmp_path):
    data = dash.build(_db(tmp_path, _burst_days("2026-03-05")))
    hot = next(d for d in data["days"] if d["date"] == "2026-03-05")
    assert hot["status"] == "red"
    assert any("reflection shape" in w for w in hot["why"])
    assert any("163.5.59.20" in w for w in hot["why"])
    # every other day is untouched
    assert {d["status"] for d in data["days"] if d["date"] != "2026-03-05"} == {"green"}


def test_ordinary_retries_share_a_tuple_but_stay_green(tmp_path):
    """Real resolvers DO reuse txid+port when retrying. That must not fire."""
    data = dash.build(_db(tmp_path, _burst_days("2026-03-05", n=4)))
    hot = next(d for d in data["days"] if d["date"] == "2026-03-05")
    assert hot["status"] == "green"
    assert not any("reflection" in w for w in hot["why"])


def test_refused_burst_is_reported_but_does_not_drive_colour(tmp_path):
    """Colour grades deviation; the defenses holding is not a deviation."""
    data = dash.build(_db(tmp_path, _burst_days("2026-03-05",
                                       decision="refuse")))
    hot = next(d for d in data["days"] if d["date"] == "2026-03-05")
    assert hot["status"] == "green"
    assert any("REFUSED" in w and "reflection shape" in w for w in hot["why"])


def test_self_test_traffic_is_never_a_reflection_victim(tmp_path):
    data = dash.build(_db(tmp_path, _burst_days("2026-03-05",
                                       src_ip="127.0.0.1")))
    hot = next(d for d in data["days"] if d["date"] == "2026-03-05")
    assert hot["status"] == "green"
    assert not any("reflection" in w for w in hot["why"])


def test_reflection_burst_reports_rate_and_bytes(tmp_path):
    data = dash.build(_db(tmp_path, _burst_days("2026-03-05",
                                       n=100, span=4)))
    hot = next(d for d in data["days"] if d["date"] == "2026-03-05")
    why = " ".join(hot["why"])
    assert "100 answered TXT queries" in why
    assert "/s" in why and "KB emitted" in why
