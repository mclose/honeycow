"""tools/annotate.py — the retrospective note writer.

These tests pin the *contract*, not the prose: which days get picked, that a
note can never influence a grade, that provenance is stamped, and that the
tool never reaches the network without being asked to. The model call itself
is always stubbed — the suite must stay offline.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import tools.annotate as ann
import tools.dashboard as dash
from tests.test_dashboard import _db, _quiet


def _graded(tmp_path, loud_day="2026-03-02"):
    days = _quiet(4)
    days[loud_day] = {"dns": 9, "http": 4000}
    return _db(tmp_path, days)


def test_only_settled_non_green_days_are_selected(tmp_path):
    data = dash.build(_graded(tmp_path))
    picked = {d["date"] for d in ann.select_days(data, tmp_path / "none", False, None)}
    assert picked == {"2026-03-02"}
    for d in data["days"]:
        if d["date"] in picked:
            assert d["status"] != "green" and not d["partial"]


def test_a_day_that_already_has_a_note_is_left_alone(tmp_path):
    """A hand-written note (no frontmatter) is never touched, at any verdict."""
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text("already written")
    data = dash.build(_graded(tmp_path))
    assert ann.select_days(data, notes, False, None) == []
    # ...unless explicitly forced, which is the only way to overwrite.
    assert [d["date"] for d in ann.select_days(data, notes, True, None)] == ["2026-03-02"]


def test_partial_days_are_never_annotated(tmp_path):
    """Retrospective by construction: the verdict has to be in first."""
    from datetime import UTC, datetime
    today = datetime.now(tz=UTC).date().isoformat()
    days = _quiet(3)
    days[today] = {"dns": 9, "http": 9000}
    data = dash.build(_db(tmp_path, days))
    assert today not in [d["date"] for d in ann.select_days(data, tmp_path / "n", False, None)]


def test_note_never_changes_a_grade(tmp_path):
    """The load-bearing guarantee: colour is earned by counted evidence. A note
    is interpretation and must not feed back into the rubric."""
    db = _graded(tmp_path)
    before = {d["date"]: d["status"] for d in dash.build(db)["days"]}
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text(
        ann.render_note("Benign measurement study.", "claude-opus-5", "yellow"))
    after = {d["date"]: d["status"] for d in dash.build(db, notes)["days"]}
    assert before == after


def test_render_note_stamps_provenance_that_the_dashboard_can_read(tmp_path):
    notes = tmp_path / "notes"
    notes.mkdir()
    (notes / "2026-03-02.md").write_text(
        ann.render_note("  Padded prose.  ", "claude-opus-5", "red"))
    parsed = dash.load_narratives(notes)["2026-03-02"]
    assert parsed["source"] == "model"
    assert parsed["model"] == "claude-opus-5"
    assert parsed["text"] == "Padded prose."


def test_evidence_bundle_carries_the_rows_behind_the_fired_rules(tmp_path):
    db = _graded(tmp_path)
    data = dash.build(db)
    day = next(d for d in data["days"] if d["date"] == "2026-03-02")
    prior = data["days"][:data["days"].index(day)]
    conn = ann._connect(db)
    ev = ann.gather_evidence(conn, day, prior)
    conn.close()
    assert ev["date"] == "2026-03-02"
    assert ev["rules_that_fired"] == day["why"]
    assert ev["counts"]["http_requests"] == day["http"]
    # The talker breakdown is the point — a bundle of totals can't be analysed.
    assert ev["http_talkers"], "expected per-source HTTP detail"
    assert "prior_non_green_days" in ev
    assert json.dumps(ev, default=str)  # must survive serialization to the API


def test_dry_run_writes_nothing_and_calls_nothing(tmp_path, monkeypatch):
    db = _graded(tmp_path)
    notes = tmp_path / "notes"

    def _boom(*a, **k):
        raise AssertionError("--dry-run must not construct a client")

    monkeypatch.setattr(ann, "_client", _boom)
    assert ann.main(["--db", str(db), "--notes", str(notes), "--dry-run"]) == 0
    assert not notes.exists() or list(notes.glob("*.md")) == []


def test_max_days_caps_the_number_of_api_calls(tmp_path, monkeypatch):
    """A rebuild must not fan out into one API call per historical bad day."""
    days = _quiet(6)
    # Alternate loud/quiet: a run of consecutive loud days pulls the trailing
    # median up and stops grading itself non-green, which would defeat the test.
    for d in ("2026-03-02", "2026-03-04", "2026-03-06"):
        days[d] = {"dns": 9, "http": 4000}
    db = _db(tmp_path, days)
    notes = tmp_path / "notes"
    picked = ann.select_days(dash.build(db), notes, False, None)
    assert len(picked) >= 3, f"fixture should offer >2 days, got {len(picked)}"

    calls = []
    monkeypatch.setattr(ann, "_client", lambda key: object())
    monkeypatch.setattr(ann, "annotate_day",
                        lambda c, m, ev, x: calls.append(ev["date"]) or "note")
    ann.main(["--db", str(db), "--notes", str(notes), "--max-days", "2"])
    assert len(calls) == 2, f"cap ignored: {calls}"
    # The cap keeps the MOST RECENT days — a stale backlog must not crowd out
    # the day the operator is most likely to be looking at.
    assert calls == [d["date"] for d in picked[-2:]]
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["deferred_by_cap"] == len(picked) - 2


def test_a_failing_day_still_records_status_and_exits_nonzero(tmp_path, monkeypatch):
    """Silence is the failure mode that matters: if the model call breaks, the
    run must leave evidence on disk rather than looking like a quiet day."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    monkeypatch.setattr(ann, "_client", lambda key: object())
    monkeypatch.setattr(ann, "annotate_day",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("429 nope")))
    rc = ann.main(["--db", str(db), "--notes", str(notes)])
    assert rc == 1
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["ok"] is False
    assert "429 nope" in status["error"]
    assert status["written"] == []


def test_successful_run_writes_note_and_clears_status(tmp_path, monkeypatch):
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    monkeypatch.setattr(ann, "_client", lambda key: object())
    usage = SimpleNamespace(input_tokens=12_000, output_tokens=2_000,
                            cache_creation_input_tokens=0, cache_read_input_tokens=0)
    monkeypatch.setattr(ann, "annotate_day",
                        lambda *a, **k: ("A known scanner fleet.", usage, "claude-opus-5"))
    assert ann.main(["--db", str(db), "--notes", str(notes)]) == 0
    note = (notes / "2026-03-02.md").read_text()
    assert "A known scanner fleet." in note
    assert "source: model" in note
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["ok"] is True and status["written"] == ["2026-03-02"]
    # 12K in + 2K out on Opus 5 = $0.06 + $0.05. A run must say what it spent.
    assert status["estimated_usd"] == pytest.approx(0.11, abs=0.005)
    # And the dashboard now reports a clean bill of health.
    assert dash.build(db, notes)["annotator"]["missing"] == []


def test_taxonomy_context_is_optional_and_never_fatal(tmp_path):
    assert ann.load_cve_context(None) == []
    assert ann.load_cve_context(tmp_path / "nope") == []
    tax = tmp_path / "tax"
    tax.mkdir()
    (tax / "cve_2026_5946.yaml").write_text(
        'cve_id: CVE-2026-5946\nvendor: ISC\nproduct: BIND 9\n'
        'vulnerability_class: dos\naxis: trigger\nconfidence: high\n'
        'references:\n- https://example.test/a\n')
    got = ann.load_cve_context(tax)
    assert got and got[0]["cve_id"] == "CVE-2026-5946"
    assert got[0]["vendor"] == "ISC"
    assert got[0]["vulnerability_class"] == "dos"
    # Nested list values must not be scraped as scalars.
    assert "references" not in got[0]


@pytest.mark.parametrize("rule,key", [
    ("cve", "cve_trigger_queries"),
    ("exploit", "exploit_probes"),
])
def test_rule_specific_detail_is_only_gathered_when_that_rule_fired(tmp_path, rule, key):
    db = _graded(tmp_path)
    data = dash.build(db)
    day = next(d for d in data["days"] if d["date"] == "2026-03-02")
    conn = ann._connect(db)
    ev = ann.gather_evidence(conn, day, [])
    conn.close()
    fired = any(rule in w.lower() for w in day["why"])
    assert (key in ev) == fired


def test_bundle_hands_over_the_rubrics_own_inputs(tmp_path):
    """Regression: the model once summed the family breakdown to re-derive the
    exploit count, included `env-harvest` (which the rule excludes), and
    confidently reported a rule as misfiring when it had worked correctly.
    The authoritative values must travel in the bundle."""
    db = _graded(tmp_path)
    data = dash.build(db)
    day = next(d for d in data["days"] if d["date"] == "2026-03-02")
    conn = ann._connect(db)
    ev = ann.gather_evidence(conn, day, [])
    conn.close()
    ri = ev["rubric_inputs"]
    assert ri["exploit_probes_counted"] == day["exploit"]
    # Both the graded (deduplicated) and the raw count must travel: a note that
    # compares the raw total against the baseline re-derives a ratio the rule
    # deliberately stopped computing.
    assert ri["exploit_probes_raw"] == day["exploit_raw"]
    assert ri["exploit_distinct_path_scripts"] == day["exploit_kits"]
    assert ri["cve_trigger_queries_counted"] == day["cve_trigger"]
    assert set(ri["exploit_families_counted"]) == set(dash.EXPLOIT_FAMILIES)
    assert "env-harvest" not in ri["exploit_families_counted"]
    assert ri["thresholds"]["exploit_spike_yellow"] == dash.RUBRIC["exploit_spike_yellow"]


def test_user_agents_are_ranked_within_each_talker(tmp_path):
    """A global top-N of (ip, ua) pairs misrepresents a loud talker that
    rotates identities — it samples the busiest pairs, not that IP's profile."""
    db = _graded(tmp_path)
    data = dash.build(db)
    day = next(d for d in data["days"] if d["date"] == "2026-03-02")
    conn = ann._connect(db)
    ev = ann.gather_evidence(conn, day, [])
    conn.close()
    assert ev["talker_ua_diversity"], "expected per-talker identity counts"
    for row in ev["talker_ua_diversity"]:
        assert row["distinct_user_agents"] >= 1
        assert row["requests"] >= row["distinct_user_agents"]


def test_a_note_written_against_a_stale_verdict_is_regenerated(tmp_path):
    """The rubric is expected to be tweaked. When a day goes red -> yellow, its
    note still opens "the red is..." — that must not survive silently."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    data = dash.build(db)
    day = next(d for d in data["days"] if d["status"] != "green" and not d["partial"])
    (notes / f"{day['date']}.md").write_text(
        ann.render_note("The red is one burst.", "claude-opus-5", "red"))
    picked = [d["date"] for d in ann.select_days(data, notes, False, None)]
    if day["status"] != "red":
        assert day["date"] in picked, "stale verdict must be regenerated"
    # A note matching the current verdict is left alone.
    (notes / f"{day['date']}.md").write_text(
        ann.render_note("Current.", "claude-opus-5", day["status"]))
    assert ann.select_days(data, notes, False, None) == []


def test_regrading_to_green_prunes_the_model_note(tmp_path):
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    data = dash.build(db)
    green = next(d for d in data["days"] if d["status"] == "green" and not d["partial"])
    stale = notes / f"{green['date']}.md"
    stale.write_text(ann.render_note("The red is one burst.", "claude-opus-5", "red"))
    assert ann.prune_stale_notes(data, notes, dry_run=False) == [green["date"]]
    assert not stale.exists()


def test_pruning_never_deletes_a_hand_written_note(tmp_path):
    """A person wrote that on purpose. The day being quiet now is not a reason
    to throw their reasoning away."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    data = dash.build(db)
    green = next(d for d in data["days"] if d["status"] == "green" and not d["partial"])
    human = notes / f"{green['date']}.md"
    human.write_text("I checked this by hand; the burst was our own scanner.")
    assert ann.prune_stale_notes(data, notes, dry_run=False) == []
    assert human.exists()


def test_prune_dry_run_deletes_nothing(tmp_path):
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    data = dash.build(db)
    green = next(d for d in data["days"] if d["status"] == "green" and not d["partial"])
    stale = notes / f"{green['date']}.md"
    stale.write_text(ann.render_note("stale", "claude-opus-5", "red"))
    assert ann.prune_stale_notes(data, notes, dry_run=True) == [green["date"]]
    assert stale.exists()


# --- scope and staleness --------------------------------------------------

def _note(notes, date, *, status, rubric=None, source="model"):
    notes.mkdir(parents=True, exist_ok=True)
    fm = f"---\nsource: {source}\nmodel: m\nstatus: {status}\n"
    if rubric:
        fm += f"rubric: {rubric}\n"
    (notes / f"{date}.md").write_text(fm + "---\nprose")


def test_green_days_are_skipped_by_default_and_covered_with_all_days(tmp_path):
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    notes.mkdir()
    default = {d["date"] for d in ann.select_days(data, notes, False, None)}
    every = {d["date"] for d in ann.select_days(data, notes, False, None, all_days=True)}
    assert default and default < every, "--all-days must be a superset"
    assert all(d["status"] != "green"
               for d in ann.select_days(data, notes, False, None))
    # Never today: a partial day's counts are not comparable to a full one.
    assert not any(d["partial"]
                   for d in ann.select_days(data, notes, False, None, all_days=True))


def test_a_note_written_against_an_old_rubric_is_regenerated(tmp_path):
    """The quiet staleness case: the threshold moved, the colour did not, and
    the prose keeps quoting a ratio nothing computes any more."""
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    day = next(d for d in data["days"] if d["status"] != "green" and not d["partial"])

    _note(notes, day["date"], status=day["status"], rubric=ann.rubric_fingerprint())
    assert day["date"] not in {d["date"] for d in ann.select_days(data, notes, False, None)}

    _note(notes, day["date"], status=day["status"], rubric="deadbeef1234")
    assert day["date"] in {d["date"] for d in ann.select_days(data, notes, False, None)}

    # A note predating the stamp entirely is also stale — it was written
    # against some rubric, just not a recorded one.
    _note(notes, day["date"], status=day["status"])
    assert day["date"] in {d["date"] for d in ann.select_days(data, notes, False, None)}


def test_a_hand_written_note_is_never_regenerated_by_a_rubric_change(tmp_path):
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    day = next(d for d in data["days"] if d["status"] != "green" and not d["partial"])
    _note(notes, day["date"], status="red", rubric="deadbeef1234", source="human")
    assert day["date"] not in {d["date"] for d in ann.select_days(data, notes, False, None)}


def test_rubric_fingerprint_moves_only_when_the_rubric_does(monkeypatch):
    before = ann.rubric_fingerprint()
    assert before == ann.rubric_fingerprint(), "must be deterministic"
    monkeypatch.setitem(dash.RUBRIC, "exploit_spike_yellow", 99.0)
    assert ann.rubric_fingerprint() != before


def test_a_green_note_on_a_green_day_survives_either_scope(tmp_path):
    """Regression, 2026-09-24: pruning keyed on the RUN's scope instead of the
    note's own verdict, so one invocation without --all-days deleted every
    green note on disk and the next run paid to rewrite them. A note that says
    green on a day that is green misrepresents nothing under any scope."""
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    green = next(d for d in data["days"] if d["status"] == "green" and not d["partial"])
    _note(notes, green["date"], status="green", rubric=ann.rubric_fingerprint())
    assert ann.prune_stale_notes(data, notes, dry_run=True, all_days=True) == []
    assert ann.prune_stale_notes(data, notes, dry_run=True) == []


def test_a_note_arguing_about_a_colour_that_is_gone_is_still_pruned(tmp_path):
    """The case pruning exists for: the day regraded green and the note still
    opens "the red is...". Nothing will rewrite it, so it has to go."""
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    green = next(d for d in data["days"] if d["status"] == "green" and not d["partial"])
    _note(notes, green["date"], status="red", rubric=ann.rubric_fingerprint())
    assert green["date"] in ann.prune_stale_notes(data, notes, dry_run=True)
    # ...but under --all-days `select_days` rewrites it in place instead.
    assert ann.prune_stale_notes(data, notes, dry_run=True, all_days=True) == []
    assert green["date"] in {d["date"]
                             for d in ann.select_days(data, notes, False, None, all_days=True)}


def test_a_stale_verdict_on_a_still_graded_day_is_rewritten_not_deleted(tmp_path):
    """A note claiming green on a day that is now yellow must not be pruned —
    `select_days` owns that case, and deleting it would lose the slot."""
    db = _graded(tmp_path)
    data = dash.build(db)
    notes = tmp_path / "notes"
    graded = next(d for d in data["days"] if d["status"] != "green" and not d["partial"])
    _note(notes, graded["date"], status="green", rubric=ann.rubric_fingerprint())
    assert ann.prune_stale_notes(data, notes, dry_run=True) == []
    assert graded["date"] in {d["date"] for d in ann.select_days(data, notes, False, None)}


def test_health_counts_green_gaps_only_when_the_annotator_claims_them(tmp_path):
    """The count stays computed from the data; only the SCOPE is self-reported,
    and an absent or unreadable status file falls back to the narrow claim."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    notes.mkdir()
    narrow = dash.build(db, notes)["annotator"]
    assert all(d["status"] != "green"
               for d in dash.build(db, notes)["days"] if d["date"] in narrow["missing"])

    (notes / ann.STATUS_FILE).write_text(json.dumps({"coverage": "all", "ok": True}))
    wide = dash.build(db, notes)["annotator"]
    assert set(narrow["missing"]) < set(wide["missing"])

    (notes / ann.STATUS_FILE).write_text("{not json")
    broken = dash.build(db, notes)["annotator"]
    assert broken["missing"] == narrow["missing"], "a broken file must understate, not invent"


def test_a_refusal_is_a_coverage_gap_not_a_broken_annotator(tmp_path, monkeypatch):
    """2026-09-19 came back `category='cyber'` — unsurprising when the payload
    is exploit paths and scanner UAs. A recurring decline must not leave the
    health line permanently red, or it stops being read; the day still has to
    be named."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    monkeypatch.setattr(ann, "_client", lambda key: object())
    monkeypatch.setattr(ann, "annotate_day",
                        lambda *a, **k: (_ for _ in ()).throw(ann.Refused("cyber")))
    assert ann.main(["--db", str(db), "--notes", str(notes)]) == 0
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["ok"] is True, "a decline is not a malfunction"
    assert status["error"] is None
    assert [r["category"] for r in status["refused"]] == ["cyber"]
    assert status["written"] == []
    assert not (notes / "2026-03-02.md").exists(), "no note is better than a wrong one"


def test_a_real_failure_still_marks_the_run_not_ok(tmp_path, monkeypatch):
    """The other side of the same boundary — a broken client must still be loud."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    monkeypatch.setattr(ann, "_client", lambda key: object())
    monkeypatch.setattr(ann, "annotate_day",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("500 boom")))
    assert ann.main(["--db", str(db), "--notes", str(notes)]) == 1
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["ok"] is False and "500 boom" in status["error"]


def test_the_byline_names_the_model_that_actually_wrote_it(tmp_path, monkeypatch):
    """A cyber refusal routes to Opus 4.8. If the note still claims Opus 5, the
    provenance stamp is a lie — and provenance is the whole point of the slot."""
    db = _graded(tmp_path)
    notes = tmp_path / "notes"
    usage = SimpleNamespace(input_tokens=1, output_tokens=1,
                            cache_creation_input_tokens=0, cache_read_input_tokens=0)
    monkeypatch.setattr(ann, "_client", lambda key: object())
    monkeypatch.setattr(ann, "annotate_day",
                        lambda *a, **k: ("Fallback prose.", usage, "claude-opus-4-8"))
    assert ann.main(["--db", str(db), "--notes", str(notes)]) == 0
    assert "model: claude-opus-4-8" in (notes / "2026-03-02.md").read_text()
