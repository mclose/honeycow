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
