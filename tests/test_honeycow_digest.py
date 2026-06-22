"""honeycow_digest is the shared parse+classify home for both the central
report and the (forthcoming) cow-side digest emitter.

These tests pin two things PR-A must hold:
  1. The classifier behaves identically whether imported from the shared
     lib or from morning_report (which re-exports it for compatibility).
  2. The lib is self-contained — importable without morning_report.
"""

from __future__ import annotations

import tools.honeycow_digest as digest
import tools.morning_report as report


def test_morning_report_reexports_are_the_same_objects():
    # The report must not carry its own divergent copy of the classifier.
    assert report.classify_query is digest.classify_query
    assert report.classify_research_scanner is digest.classify_research_scanner
    assert report.FLAG_RD is digest.FLAG_RD


def test_classifier_runs_from_the_lib_directly():
    ev = {"qname": "version.bind.", "qclass_name": "CH", "qtype_name": "TXT"}
    assert digest.classify_query(ev) == "chaos-banner"
    assert digest.classify_research_scanner("x.shadowserver.org.") == "shadowserver"


# --- digest emitter (PR-C) --------------------------------------------------

from datetime import datetime  # noqa: E402


def _q(src_ip, qname="x.example.", qclass="IN", qtype="A", handler="synth_a",
       response_kind="NOERROR", ts="2026-06-22T14:05:00+00:00"):
    return {
        "event": "query", "src_ip": src_ip, "qname": qname,
        "qclass_name": qclass, "qtype_name": qtype, "opcode": "QUERY",
        "handler": handler, "response_kind": response_kind, "ts": ts,
        "_ts": datetime.fromisoformat(ts),
    }


def _http(ip, path="/.env", ua="curl", ts="2026-06-22T14:06:00+00:00"):
    return {
        "event": "http_closer", "client_ip": ip, "path": path,
        "user_agent": ua, "ts": ts, "_ts": datetime.fromisoformat(ts),
    }


def _ufw(src, dpt="80", proto="TCP", ts="2026-06-22T14:07:00+00:00"):
    return {"src": src, "dpt": dpt, "proto": proto,
            "ts": datetime.fromisoformat(ts)}


def test_summarize_window_schema_and_totals():
    events = [
        _q("45.33.12.1"),
        _q("45.33.12.1", qname="version.bind.", qclass="CH", qtype="TXT",
           handler="synth_txt_ch_version_bind"),
        _http("45.33.12.9"),
        _q("127.0.0.1"),  # internal: excluded from dns_external
    ]
    ufw = [_ufw("45.33.12.1"), _ufw("45.33.12.1", dpt="23")]
    d = digest.summarize_window(events, ufw, site_id="ams-01",
                                hour_iso="2026-06-22T14:00:00+00:00")
    assert d["schema"] == digest.DIGEST_SCHEMA
    assert d["site_id"] == "ams-01"
    assert d["totals"]["events"] == 4
    assert d["totals"]["dns_queries"] == 3
    assert d["totals"]["dns_external"] == 2  # loopback excluded
    assert d["totals"]["http"] == 1
    assert d["totals"]["ufw"] == 2
    # family rollup over external queries only
    assert d["families"]["other"] == 1
    assert d["families"]["chaos-banner"] == 1


def test_by_src_rollup():
    events = [_q("45.33.12.1", qtype="A"), _q("45.33.12.1", qtype="TXT")]
    ufw = [_ufw("45.33.12.1", dpt="80"), _ufw("45.33.12.1", dpt="80")]
    d = digest.summarize_window(events, ufw, site_id="x",
                                hour_iso="2026-06-22T14:00:00+00:00")
    s = d["by_src"]["45.33.12.1"]
    assert s["dns"] == 2
    assert s["ufw"] == 2
    assert s["qtypes"] == {"A": 1, "TXT": 1}
    assert s["ufw_ports"] == {"tcp/80": 2}
    assert s["first"] == "2026-06-22T14:05:00+00:00"


def test_source_exempt_and_research_rollups():
    events = [
        _q("45.33.12.5", handler="exempt_source"),
        _q("45.33.12.5", handler="exempt_source"),
        _q("185.107.56.2", qname="dnsscan.shadowserver.org.",
           handler="exempt", response_kind="REFUSED"),
    ]
    d = digest.summarize_window(events, [], site_id="x",
                                hour_iso="2026-06-22T14:00:00+00:00")
    assert d["source_exempt"]["45.33.12.5"] == 2
    assert d["research_scanners"]["shadowserver"]["hits"] == 1
    assert d["research_scanners"]["shadowserver"]["refused"] == 1


def test_inbound_qr_and_cve_exemplar():
    drop = {
        "event": "query_drop", "src_ip": "45.33.13.50", "src_port": 53,
        "drop_reason": "oversized_datagram", "ts": "2026-06-22T14:01:00+00:00",
        "_ts": datetime.fromisoformat("2026-06-22T14:01:00+00:00"),
    }
    cve = _q("45.33.13.99", qname="honeycow.net.", qclass="CH", qtype="A")
    d = digest.summarize_window([cve, drop], [], site_id="x",
                                hour_iso="2026-06-22T14:00:00+00:00")
    assert d["inbound_qr"]["total"] == 1
    assert d["inbound_qr"]["oversized_total"] == 1
    assert len(d["qr_exemplars"]) == 1
    assert len(d["cve_exemplars"]) == 1
    assert d["cve_exemplars"][0]["qname"] == "honeycow.net."


def test_hourly_bucketing_splits_by_hour():
    events = [
        _q("45.33.12.1", ts="2026-06-22T14:05:00+00:00"),
        _q("45.33.12.2", ts="2026-06-22T15:05:00+00:00"),
        _q("45.33.12.3", ts="2026-06-22T15:45:00+00:00"),
    ]
    digs = digest.iter_hourly_digests(events, [], site_id="x")
    assert len(digs) == 2
    assert digs[0]["hour"] == "2026-06-22T14:00:00+00:00"
    assert digs[0]["totals"]["dns_external"] == 1
    assert digs[1]["totals"]["dns_external"] == 2


def test_digest_merge_is_lossless_for_totals_and_families():
    # The PR-D contract in miniature: summing per-hour digests reproduces the
    # direct counts for the dimensions the digest keeps.
    events = [
        _q("45.33.12.1", ts="2026-06-22T14:05:00+00:00"),
        _q("45.33.12.1", qname="version.bind.", qclass="CH", qtype="TXT",
           ts="2026-06-22T14:30:00+00:00"),
        _q("45.33.12.2", ts="2026-06-22T15:05:00+00:00"),
    ]
    import collections
    direct = collections.Counter(digest.classify_query(e) for e in events)
    digs = digest.iter_hourly_digests(events, [], site_id="x")
    merged = collections.Counter()
    total_ext = 0
    for d in digs:
        merged.update(d["families"])
        total_ext += d["totals"]["dns_external"]
    assert dict(merged) == dict(direct)
    assert total_ext == len(events)
