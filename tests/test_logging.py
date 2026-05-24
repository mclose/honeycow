"""Event-record shape."""

from __future__ import annotations

import dns.message
import dns.name
import dns.rdatatype

import honey_logging


def test_event_includes_question():
    q = dns.message.make_query(
        dns.name.from_text("scan.example.com."), dns.rdatatype.A,
    )
    rec = honey_logging.event(
        event="query",
        request_id="abc",
        transport="udp",
        src_ip="198.51.100.1",
        src_port=12345,
        dst_bind="0.0.0.0:53",
        raw_len=32,
        query=q,
        response_kind="NOERROR",
    )
    assert rec["qname"] == "scan.example.com."
    assert rec["qtype_name"] == "A"
    assert rec["src_ip"] == "198.51.100.1"
    assert rec["schema_version"] == honey_logging.SCHEMA_VERSION


def test_event_omits_edns_fields_when_no_opt():
    q = dns.message.make_query(
        dns.name.from_text("scan.example.com."), dns.rdatatype.A,
        use_edns=False,
    )
    rec = honey_logging.event(
        event="query", request_id="x", transport="udp",
        src_ip="198.51.100.1", src_port=1, dst_bind="0.0.0.0:53",
        raw_len=32, query=q, response_kind="NOERROR",
    )
    assert "edns_version" not in rec
    assert "do_set" not in rec


def test_event_includes_edns_when_opt_present():
    import dns.edns
    q = dns.message.make_query(
        dns.name.from_text("scan.example.com."), dns.rdatatype.A,
        use_edns=0, want_dnssec=True, payload=4096,
        options=[dns.edns.GenericOption(dns.edns.NSID, b"\x01\x02\x03")],
    )
    rec = honey_logging.event(
        event="query", request_id="x", transport="udp",
        src_ip="198.51.100.1", src_port=1, dst_bind="0.0.0.0:53",
        raw_len=32, query=q, response_kind="NOERROR",
    )
    assert rec["edns_version"] == 0
    assert rec["edns_payload"] == 4096
    assert rec["do_set"] is True
    assert isinstance(rec["edns_flags"], int)
    assert int(dns.edns.NSID) in rec["edns_options"]
    # Per-option raw wire bytes preserved for future signature work.
    nsid_raw = next(
        o for o in rec["edns_options_raw"] if o["otype"] == int(dns.edns.NSID)
    )
    assert nsid_raw["data_hex"] == "010203"


def test_event_handles_missing_query():
    rec = honey_logging.event(
        event="query_drop",
        request_id="abc",
        transport="udp",
        src_ip="198.51.100.1",
        src_port=12345,
        dst_bind="0.0.0.0:53",
        raw_len=32,
        response_kind="DROPPED",
        drop_reason="oversized_datagram",
    )
    assert "qname" not in rec
    assert rec["drop_reason"] == "oversized_datagram"
