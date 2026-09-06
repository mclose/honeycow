"""tools/annotate.py — the retrospective note writer.

These tests pin the *contract*, not the prose: which days get picked, that a
note can never influence a grade, that provenance is stamped, and that the
tool never reaches the network without being asked to. The model call itself
is always stubbed — the suite must stay offline.
"""

from __future__ import annotations

import json

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
    monkeypatch.setattr(ann, "annotate_day", lambda *a, **k: "A known scanner fleet.")
    assert ann.main(["--db", str(db), "--notes", str(notes)]) == 0
    note = (notes / "2026-03-02.md").read_text()
    assert "A known scanner fleet." in note
    assert "source: model" in note
    status = json.loads((notes / ann.STATUS_FILE).read_text())
    assert status["ok"] is True and status["written"] == ["2026-03-02"]
    # And the dashboard now reports a clean bill of health.
    assert dash.build(db, notes)["annotator"]["missing"] == []


def test_taxonomy_context_is_optional_and_never_fatal(tmp_path):
    assert ann.load_cve_context(None) == []
    assert ann.load_cve_context(tmp_path / "nope") == []
    tax = tmp_path / "tax"
    tax.mkdir()
    (tax / "cve_2026_5946.yaml").write_text(
        'id: cve-2026-5946\ntitle: "BIND non-IN class"\naxis: trigger\n'
        'match:\n  qclass: [CH, HS]\n')
    got = ann.load_cve_context(tax)
    assert got and got[0]["id"] == "cve-2026-5946"
    assert got[0]["title"] == "BIND non-IN class"
    assert "match" not in got[0]  # nested keys are not scraped as scalars


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
