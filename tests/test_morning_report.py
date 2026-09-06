"""morning_report.classify_query — banner-vs-CVE boundary.

The `cve-2026-5946-trigger` bucket must mean what its name claims: a non-IN
class query that exercises BIND's non-IN-class code path, NOT a plain
`version.bind` banner probe that merely happened to arrive with RD=1. RD=1 on
a CHAOS query is a ubiquitous scanner default, not exploit intent, so it must
never promote a banner probe into the CVE bucket.
"""

from __future__ import annotations

from tools.morning_report import FLAG_RD, classify_query


def _ev(qname, qclass="IN", qtype="TXT", opcode="QUERY", rd=False):
    return {
        "qname": qname,
        "qclass_name": qclass,
        "qtype_name": qtype,
        "opcode": opcode,
        "flags": FLAG_RD if rd else 0,
    }


# --- banner fingerprinting stays `chaos-banner` regardless of RD/qtype ------


def test_version_bind_is_banner_without_rd():
    assert classify_query(_ev("version.bind.", "CH", "TXT")) == "chaos-banner"


def test_version_bind_is_banner_even_with_rd():
    # The whole point: RD=1 must not flip a banner probe into the CVE bucket.
    assert classify_query(_ev("version.bind.", "CH", "TXT", rd=True)) == "chaos-banner"


def test_banner_with_qtype_a_is_still_banner():
    # `CH/A version.bind.` is sloppy but plainly recon, not the CVE path.
    assert classify_query(_ev("version.bind.", "CH", "A", rd=True)) == "chaos-banner"


def test_known_banner_variants_recognized():
    for qname in (
        "hostname.bind.",
        "id.server.",
        "authors.bind.",
        "version.server.",
        "hostname.server.",
        "id.bind.",
    ):
        assert classify_query(_ev(qname, "CH", "TXT", rd=True)) == "chaos-banner", qname


# --- genuinely off-pattern non-IN shapes ARE the CVE trigger ----------------


def test_non_banner_qname_in_chaos_is_cve():
    assert classify_query(_ev("honeycow.net.", "CH", "A")) == "cve-2026-5946-trigger"


def test_chaos_axfr_is_cve():
    assert classify_query(_ev("honeycow.net.", "CH", "AXFR")) == "cve-2026-5946-trigger"


def test_hesiod_class_is_cve():
    assert classify_query(_ev("a.", "HS", "A")) == "cve-2026-5946-trigger"


def test_banner_qname_with_non_query_opcode_is_cve():
    # Banner name but a non-QUERY opcode exercises the non-IN-class path.
    assert (
        classify_query(_ev("version.bind.", "CH", "TXT", opcode="NOTIFY"))
        == "cve-2026-5946-trigger"
    )


def test_junk_qname_in_chaos_is_cve():
    assert classify_query(_ev("random.scanner.fingerprint.", "CH", "TXT")) == (
        "cve-2026-5946-trigger"
    )


# --- IN-class and empty fall through to their own buckets -------------------


def test_in_class_banner_qname_is_banner_not_cve():
    # `TXT version.bind` in class IN — scanner that didn't bother with CHAOS.
    assert classify_query(_ev("version.bind.", "IN", "TXT")) == "chaos-banner"


def test_empty_qname():
    assert classify_query(_ev("", "CH", "TXT")) == "empty"


# --- herd render (PR-D) -----------------------------------------------------

def test_render_herd_smoke(capsys):
    """A merged digest renders the herd report without raw events."""
    from tools import morning_report
    from tools.honeycow_digest import iter_hourly_digests, merge_digests

    events = [
        _ev_q("45.33.12.1", "x.example."),
        _ev_q("45.33.12.1", "version.bind.", qclass="CH"),
        _ev_q("45.33.12.2", "honeycow.net.", qclass="CH"),
    ]
    merged = merge_digests(iter_hourly_digests(events, [], site_id="ams-01"))
    morning_report.render_herd(merged)
    out = capsys.readouterr().out
    assert "=== totals ===" in out
    assert "=== DNS probe families ===" in out
    assert "=== fan-out" in out
    assert "chaos-banner" in out
    assert "cve-2026-5946-trigger" in out


def _ev_q(src_ip, qname, qclass="IN", qtype="A"):
    from datetime import datetime
    return {
        "event": "query", "src_ip": src_ip, "qname": qname,
        "qclass_name": qclass, "qtype_name": qtype, "opcode": "QUERY",
        "handler": "synth_a", "response_kind": "NOERROR",
        "ts": "2026-06-22T14:05:00+00:00",
        "_ts": datetime.fromisoformat("2026-06-22T14:05:00+00:00"),
    }


def test_promotions_announce_new_signatures_in_window(tmp_path):
    """Promotion is automatic, so the report is where a new signature announces
    itself — the operator never visits the queue."""
    from datetime import UTC, datetime, timedelta

    from tools.morning_report import load_promotions

    p = tmp_path / "promotions.jsonl"
    p.write_text(
        '{"date": "2026-09-06", "cve_id": "CVE-2026-1", "title": "Fresh"}\n'
        '{"date": "2026-01-01", "cve_id": "CVE-2026-0", "title": "Stale"}\n')
    since = datetime(2026, 9, 6, tzinfo=UTC) - timedelta(hours=24)
    got = load_promotions(p, since)
    assert [r["cve_id"] for r in got] == ["CVE-2026-1"]


def test_promotions_reader_never_breaks_the_report(tmp_path):
    """A cross-repo file we don't control must not be able to cost you the
    morning report — missing, malformed, or half-written all degrade to []."""
    from datetime import UTC, datetime

    from tools.morning_report import load_promotions

    since = datetime(2026, 9, 6, tzinfo=UTC)
    assert load_promotions(None, since) == []
    assert load_promotions(tmp_path / "absent.jsonl", since) == []
    bad = tmp_path / "bad.jsonl"
    bad.write_text('not json\n{"date": "nope", "cve_id": "X"}\n{"no_date": 1}\n\n')
    assert load_promotions(bad, since) == []
