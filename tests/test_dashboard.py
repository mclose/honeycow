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

        # Exploit-family probes with explicit per-source path lists, so a test
        # can express "N sources running the same script" vs "N behaviours".
        for k_i, kit in enumerate(spec.get("kits", [])):
            for p_i, path in enumerate(kit["paths"]):
                http.append((f"kit-{day}-{k_i}-{p_i}", f"{day}T12:00:00+00:00", 0,
                             "1.2.3.4", 5000, None, kit["src_ip"], None, "GET",
                             path, "h", "ua", 10, 10, 1.0,
                             kit.get("family", "phpunit-rce")))

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



def test_volume_grade_uses_the_day_minus_its_loudest_source(tmp_path):
    """The adjusted figure must stay on the same scale as the raw one, so it is
    a subtraction from the total rather than a re-sum of external sources."""
    data = dash.build(_db(tmp_path, _quiet(6)))
    for d in data["days"]:
        top = d["http_top"]
        assert d["http_ex_top"] == max(d["http"] - (top[1] if top else 0), 0)


def test_single_source_line_is_reported_but_never_graded(tmp_path):
    """The burst still gets a line on the card; it must not drive colour."""
    baseline = {"http": 400, "dns": 3000}
    day = {"http": 100_000, "dns_queries": 3000, "dns_drops": 0,
           "http_ex_top": 100, "dns_ex_top": 3000,
           "http_top": ["9.9.9.9", 99_900], "dns_top": None,
           "exploit": 0, "cve_trigger": 0, "qr_oversized_nonresearch": 0,
           "reflection_bursts": [], "new_sources": 0,
           "baseline": {"new_sources": 1}}
    base = {"http": 400.0, "dns": 3000.0, "exploit": 1, "new_sources": 1}
    status, why = dash.grade_day(day, base)
    assert status == "green", f"a single-source flood must not colour the day: {why}"
    assert any("one source" in w for w in why), "but it must still be reported"
    assert any("99,900" in w for w in why)


def test_a_genuine_breadth_spike_still_grades(tmp_path):
    """The rule must keep its teeth: many sources spiking is the real signal."""
    day = {"http": 5000, "dns_queries": 3000, "dns_drops": 0,
           "http_ex_top": 4800, "dns_ex_top": 3000,
           "http_top": ["9.9.9.9", 200], "dns_top": None,
           "exploit": 0, "cve_trigger": 0, "qr_oversized_nonresearch": 0,
           "reflection_bursts": [], "new_sources": 0,
           "baseline": {"new_sources": 1}}
    base = {"http": 400.0, "dns": 3000.0, "exploit": 1, "new_sources": 1}
    status, why = dash.grade_day(day, base)
    assert status == "red", f"broad spike should still be red: {why}"
    assert any("excluding the busiest source" in w for w in why)


def test_graded_reasons_lead_the_card(tmp_path):
    """The ungraded burst note must not appear above the reason for the colour,
    or the card reads as though the burst caused it."""
    day = {"http": 10_000, "dns_queries": 3000, "dns_drops": 0,
           "http_ex_top": 100, "dns_ex_top": 3000,
           "http_top": ["9.9.9.9", 9900], "dns_top": None,
           "exploit": 0, "cve_trigger": 7, "qr_oversized_nonresearch": 0,
           "reflection_bursts": [], "new_sources": 0,
           "baseline": {"new_sources": 1}}
    base = {"http": 400.0, "dns": 3000.0, "exploit": 1, "new_sources": 1}
    status, why = dash.grade_day(day, base)
    assert status == "yellow"
    assert "CVE" in why[0], f"graded reason must lead, got: {why}"
    assert "one source" in why[-1]


# --- exploit dedup: clones of one commodity kit are one behaviour ------------

def test_cluster_by_paths_merges_scripts_that_differ_by_one_nonce():
    """Regression from live data: the 2026-09-07 twin scanners walked the same
    637-path list but each stamped a unique `/__aws_leak_probe_<rand>__`, so
    exact-set matching split them at Jaccard 0.997."""
    shared = {f"/p{i}" for i in range(637)}
    groups = dash.cluster_by_paths(
        {"a": shared | {"/__aws_leak_probe_e1b8__"},
         "b": shared | {"/__aws_leak_probe_5fd3__"}},
        dash.RUBRIC["kit_similarity"],
    )
    assert len(groups) == 1, "one nonce path must not split one behaviour"
    assert sorted(groups[0]) == ["a", "b"]


def test_cluster_by_paths_keeps_unrelated_scripts_apart():
    groups = dash.cluster_by_paths(
        {"a": {"/x1", "/x2", "/x3"}, "b": {"/y1", "/y2", "/y3"}},
        dash.RUBRIC["kit_similarity"],
    )
    assert len(groups) == 2, "disjoint path lists are two behaviours"


def test_cluster_by_paths_does_not_chain():
    """Single-linkage would merge a and c through b, hiding a distinct
    behaviour inside a commodity cluster. Leader assignment must not."""
    groups = dash.cluster_by_paths(
        {"a": {"/1", "/2"}, "b": {"/2", "/3"}, "c": {"/3", "/4"}}, 0.3)
    assert {"a", "c"} not in [set(g) for g in groups]


def test_clone_scanners_do_not_multiply_the_exploit_count(tmp_path):
    """Four copies of one 48-path kit must count once, not four times — the
    exact arithmetic that graded 2026-07-22, 08-29 and 09-08 yellow."""
    kit = [f"/k{i}" for i in range(48)]
    rows = _quiet(30)
    rows["2026-03-31"] = {"dns": 10, "http": 100, "kits": [
        {"src_ip": f"9.9.9.{n}", "paths": kit} for n in range(4)]}
    data = dash.build(_db(tmp_path, rows))
    day = next(d for d in data["days"] if d["date"] == "2026-03-31")
    assert day["exploit_raw"] == 192, "raw count still sees every probe"
    assert day["exploit"] == 48, "four clones are one behaviour"
    assert day["exploit_kits"] == 1


def test_distinct_kits_still_add_up(tmp_path):
    """The rule must keep its teeth: genuinely different scripts accumulate."""
    rows = _quiet(30)
    rows["2026-03-31"] = {"dns": 10, "http": 100, "kits": [
        {"src_ip": "9.9.9.1", "paths": [f"/a{i}" for i in range(48)]},
        {"src_ip": "9.9.9.2", "paths": [f"/b{i}" for i in range(48)]}]}
    data = dash.build(_db(tmp_path, rows))
    day = next(d for d in data["days"] if d["date"] == "2026-03-31")
    assert day["exploit"] == 96 and day["exploit_kits"] == 2


def test_the_panel_still_shows_the_raw_probe_count(tmp_path):
    """Colour grades the deduplicated figure; the card must not hide the rest."""
    kit = [f"/k{i}" for i in range(48)]
    rows = _quiet(30, http=10)
    rows["2026-03-31"] = {"dns": 10, "http": 10, "kits": [
        {"src_ip": f"9.9.9.{n}", "paths": kit} for n in range(8)]}
    data = dash.build(_db(tmp_path, rows))
    day = next(d for d in data["days"] if d["date"] == "2026-03-31")
    fired = [w for w in day["why"] if "exploit-shaped" in w]
    assert fired, f"a real 8-clone spike should still fire: {day['why']}"
    assert "384 raw" in fired[0], f"raw count must stay visible: {fired[0]}"


def test_working_state_is_not_embedded_in_the_page(tmp_path):
    """`exploit_paths` holds sets, which are not JSON-serialisable — and the
    page has no use for per-source path lists anyway."""
    data = dash.build(_db(tmp_path, _quiet(5)))
    for day in data["days"]:
        assert "exploit_paths" not in day and "exploit_sources" not in day
    json.dumps(data)


def test_a_note_written_against_a_different_grade_is_marked_stale(tmp_path):
    """A rubric tweak regrades days underneath existing notes, and annotate.py
    is idempotent so it never revisits them. The page must say so."""
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-05.md").write_text(
        "---\nsource: model\nmodel: m\nstatus: yellow\n---\nIt was yellow because...")
    (notes / "2026-03-06.md").write_text("A hand note with no frontmatter.")
    data = dash.build(_db(tmp_path, _quiet(10)), notes)
    stale = next(d for d in data["days"] if d["date"] == "2026-03-05")
    assert stale["status"] == "green"
    assert stale["narrative"]["stale"] is True

    # No recorded grade means nothing to contradict — never cry stale on a
    # hand-written note that made no claim about colour.
    plain = next(d for d in data["days"] if d["date"] == "2026-03-06")
    assert plain["narrative"]["stale"] is False
