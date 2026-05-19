"""Dispatch behavior — exempt, class, qtype switch, NODATA fallback."""

from __future__ import annotations

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from squatter import base, dispatch
from squatter.exemptions import ExemptionList


def _make_query(
    qname: str, qtype: int, qclass: int = dns.rdataclass.IN,
) -> dns.message.Message:
    name = dns.name.from_text(qname)
    return dns.message.make_query(name, qtype, qclass)


def test_a_query_synthesizes_sinkhole():
    q = _make_query("target.example.com.", dns.rdatatype.A)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.NOERROR
    assert handler == "synth_a"
    answers = resp.answer[0]
    assert answers.rdtype == dns.rdatatype.A
    assert any(r.address == base.SINKHOLE_A for r in answers)
    assert resp.authority and resp.authority[0].rdtype == dns.rdatatype.NS
    assert resp.additional


def test_aaaa_query_synthesizes_when_v6_set():
    q = _make_query("target.example.com.", dns.rdatatype.AAAA)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    if base.SINKHOLE_AAAA:
        assert handler == "synth_aaaa"
        assert resp.answer[0].rdtype == dns.rdatatype.AAAA
    else:
        assert handler == "nodata_no_v6"
        assert resp.rcode() == dns.rcode.NOERROR
        assert not resp.answer


def test_ns_query_lists_all_ns_hosts():
    q = _make_query("anything.tld.", dns.rdatatype.NS)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_ns"
    ns_names = {r.target.to_text() for r in resp.answer[0]}
    expected = {h.to_text() for h in base.NS_HOSTS}
    assert ns_names == expected


def test_soa_query_synthesizes_at_qname():
    q = _make_query("scan.example.com.", dns.rdatatype.SOA)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_soa"
    soa_rrset = resp.answer[0]
    assert soa_rrset.name == dns.name.from_text("scan.example.com.")
    assert soa_rrset.rdtype == dns.rdatatype.SOA
    rdata = list(soa_rrset)[0]
    assert rdata.mname == base.NS_HOSTS[0]
    assert rdata.rname == base.HOSTMASTER


def test_txt_query_returns_calling_card():
    q = _make_query("anywhere.tld.", dns.rdatatype.TXT)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_txt"
    rdata = list(resp.answer[0])[0]
    text = b"".join(rdata.strings).decode("utf-8")
    assert "honeycow" in text


def test_mx_query_synthesizes_to_ns1():
    q = _make_query("mail.target.tld.", dns.rdatatype.MX)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_mx"
    mx = list(resp.answer[0])[0]
    assert mx.exchange == base.NS_HOSTS[0]
    # MX target A glue in additional.
    assert any(rr.rdtype == dns.rdatatype.A for rr in resp.additional)


def test_any_query_returns_minimal_hinfo():
    q = _make_query("scanner.tld.", dns.rdatatype.ANY)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "minimal_any_hinfo"
    assert resp.answer[0].rdtype == dns.rdatatype.HINFO
    # ANY does NOT carry authority/additional bluff — it stays minimal.
    assert not resp.authority
    assert not resp.additional


def test_axfr_refused():
    q = _make_query("example.com.", dns.rdatatype.AXFR)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "refused_xfr"


def test_ixfr_refused():
    q = _make_query("example.com.", dns.rdatatype.IXFR)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "refused_xfr"


def test_chaos_class_version_bind_returns_calling_card_by_default():
    """Without HONEY_VERSION_BIND_TXT set, version.bind gets the calling card."""
    q = _make_query("version.bind.", dns.rdatatype.TXT, qclass=dns.rdataclass.CH)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.NOERROR
    assert handler == "synth_txt_ch"
    answers = resp.answer[0]
    assert answers.rdclass == dns.rdataclass.CH
    assert answers.rdtype == dns.rdatatype.TXT
    txt_strings = b"".join(answers[0].strings)
    assert txt_strings == base.TXT_CALLING_CARD.encode("utf-8")
    # CH-class responses don't mix in IN-class auth/glue.
    assert not resp.authority
    assert not resp.additional


def test_chaos_class_version_bind_uses_themed_response_when_set(monkeypatch):
    """When HONEY_VERSION_BIND_TXT is set, version.bind gets that string."""
    themed = "BIND 9.20 fl.oz. of pure local example.com"
    monkeypatch.setattr(base, "VERSION_BIND_TXT", themed)
    q = _make_query("version.bind.", dns.rdatatype.TXT, qclass=dns.rdataclass.CH)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_txt_ch_version_bind"
    answers = resp.answer[0]
    txt_strings = b"".join(answers[0].strings)
    assert txt_strings == themed.encode("utf-8")


def test_chaos_class_other_name_still_calling_card_when_version_bind_set(monkeypatch):
    """The themed override applies only to version.bind, not other CH TXT names."""
    monkeypatch.setattr(base, "VERSION_BIND_TXT", "BIND 9.20 fl.oz. of pure local example.com")
    q = _make_query("hostname.bind.", dns.rdatatype.TXT, qclass=dns.rdataclass.CH)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_txt_ch"
    answers = resp.answer[0]
    txt_strings = b"".join(answers[0].strings)
    assert txt_strings == base.TXT_CALLING_CARD.encode("utf-8")


def test_chaos_class_any_returns_hinfo_in_ch():
    q = _make_query("hostname.bind.", dns.rdatatype.ANY, qclass=dns.rdataclass.CH)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.NOERROR
    assert handler == "minimal_any_hinfo_ch"
    answers = resp.answer[0]
    assert answers.rdclass == dns.rdataclass.CH
    assert answers.rdtype == dns.rdatatype.HINFO


def test_chaos_class_other_qtype_nodata():
    """Non-TXT/ANY CH-class queries get NOERROR / empty (not REFUSED)."""
    q = _make_query("foo.bind.", dns.rdatatype.A, qclass=dns.rdataclass.CH)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.NOERROR
    assert handler == "ch_nodata"
    assert not resp.answer


def test_unsupported_class_still_refused():
    """HESIOD (and other oddballs) remain REFUSED."""
    q = _make_query("example.com.", dns.rdatatype.TXT, qclass=dns.rdataclass.HS)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "refused_class"


def test_meta_qtype_formerr():
    q = _make_query("example.com.", dns.rdatatype.OPT)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.FORMERR
    assert handler == "formerr_meta_qtype"


def test_cname_falls_through_to_nodata():
    q = _make_query("anything.tld.", dns.rdatatype.CNAME)
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert resp.rcode() == dns.rcode.NOERROR
    assert handler == "nodata"
    assert not resp.answer
    assert resp.authority and resp.authority[0].rdtype == dns.rdatatype.SOA


def test_exempt_zone_refused(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    q = _make_query("target.example.com.", dns.rdatatype.A)
    resp, handler = dispatch.dispatch(q, el)
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "exempt"


def test_exempt_does_not_leak_to_sibling_zone(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    q = _make_query("target.example.org.", dns.rdatatype.A)
    resp, handler = dispatch.dispatch(q, el)
    assert handler == "synth_a"
