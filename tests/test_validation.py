"""Env parsing and small invariants on identity / synth helpers."""

from __future__ import annotations

import dns.name
import dns.rdatatype

from squatter import base


def test_domain_has_trailing_dot():
    assert base.DOMAIN.to_text().endswith(".")


def test_ns_hosts_nonempty():
    assert base.NS_HOSTS
    for host in base.NS_HOSTS:
        assert host.to_text().endswith(".")


def test_hostmaster_derived_from_email():
    # conftest sets HONEY_ABUSE_EMAIL=abuse@honeycow.test
    assert base.HOSTMASTER == dns.name.from_text("abuse.honeycow.test.")


def test_synth_a_rrset_round_trips():
    rrset = base.synth_a_rrset(
        dns.name.from_text("foo.example."), 300, "198.51.100.42",
    )
    assert rrset.rdtype == dns.rdatatype.A
    assert list(rrset)[0].address == "198.51.100.42"


def test_synth_aaaa_rrset_round_trips():
    rrset = base.synth_aaaa_rrset(
        dns.name.from_text("foo.example."), 300, "2001:db8::42",
    )
    assert rrset.rdtype == dns.rdatatype.AAAA


def test_synth_txt_short_string_one_chunk():
    rrset = base.synth_txt_rrset(dns.name.from_text("foo."), 300, "hello")
    strings = list(rrset)[0].strings
    assert len(strings) == 1
    assert strings[0] == b"hello"


def test_synth_txt_chunks_long_strings():
    long = "x" * 600
    rrset = base.synth_txt_rrset(dns.name.from_text("foo."), 300, long)
    strings = list(rrset)[0].strings
    assert sum(len(s) for s in strings) == 600
    assert all(len(s) <= 255 for s in strings)


def test_sinkhole_defaults_to_public():
    # conftest does not set HONEY_SINKHOLE_A, so it should equal HONEY_PUBLIC_A.
    assert base.SINKHOLE_A == base.PUBLIC_A


def test_ns_glue_includes_v6_when_aaaa_set():
    glue = base.ns_glue_rrsets(
        300, base.NS_HOSTS, "198.51.100.1", "2001:db8::1",
    )
    types = {rr.rdtype for rr in glue}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA in types


def test_ns_glue_omits_v6_when_aaaa_empty():
    glue = base.ns_glue_rrsets(300, base.NS_HOSTS, "198.51.100.1", "")
    types = {rr.rdtype for rr in glue}
    assert dns.rdatatype.A in types
    assert dns.rdatatype.AAAA not in types
