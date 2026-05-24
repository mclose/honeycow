"""Source-IP exemption list behavior."""

from __future__ import annotations

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from squatter import dispatch
from squatter.exemptions import ExemptionList
from squatter.source_exemptions import SourceExemptionList


def _query(qname: str, qtype: int = dns.rdatatype.A) -> dns.message.Message:
    return dns.message.make_query(dns.name.from_text(qname), qtype)


def test_empty_list_matches_nothing():
    sel = SourceExemptionList()
    assert not sel.is_exempt("1.2.3.4")
    assert not sel.is_exempt("2001:db8::1")


def test_loads_v4_and_v6_singletons(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("10.0.0.1\n2001:db8::1\n")
    sel = SourceExemptionList(p)
    assert len(sel) == 2
    assert sel.is_exempt("10.0.0.1")
    assert sel.is_exempt("2001:db8::1")
    assert not sel.is_exempt("10.0.0.2")
    assert not sel.is_exempt("2001:db8::2")


def test_loads_v4_cidr(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("65.49.1.16/28\n")
    sel = SourceExemptionList(p)
    assert sel.is_exempt("65.49.1.16")
    assert sel.is_exempt("65.49.1.28")  # observed shadowserver probe
    assert sel.is_exempt("65.49.1.31")
    assert not sel.is_exempt("65.49.1.32")
    assert not sel.is_exempt("65.49.1.15")


def test_loads_v6_cidr(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("2a06:4880::/29\n")
    sel = SourceExemptionList(p)
    assert sel.is_exempt("2a06:4880::1")
    assert sel.is_exempt("2a06:4887:ffff:ffff:ffff:ffff:ffff:ffff")
    assert not sel.is_exempt("2a06:4888::1")


def test_ignores_comments_and_blanks(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("# top comment\n10.0.0.1  # inline\n\n  \n2001:db8::/64\n")
    sel = SourceExemptionList(p)
    assert len(sel) == 2
    assert sel.is_exempt("10.0.0.1")
    assert sel.is_exempt("2001:db8::dead:beef")


def test_parse_failure_keeps_old_list(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("10.0.0.1\n")
    sel = SourceExemptionList(p)
    p.write_text("not-an-ip\n")
    sel.load()
    assert sel.is_exempt("10.0.0.1")


def test_reload_picks_up_changes(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("10.0.0.1\n")
    sel = SourceExemptionList(p)
    assert sel.is_exempt("10.0.0.1")
    p.write_text("10.0.0.2\n")
    sel.load()
    assert not sel.is_exempt("10.0.0.1")
    assert sel.is_exempt("10.0.0.2")


def test_unparseable_src_ip_is_not_exempt(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("10.0.0.1\n")
    sel = SourceExemptionList(p)
    assert not sel.is_exempt("")
    assert not sel.is_exempt("garbage")


def test_dispatch_refuses_exempt_source(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("65.49.1.16/28\n")
    sel = SourceExemptionList(p)
    q = _query("totally-innocent.example.com.")
    resp, handler = dispatch.dispatch(q, ExemptionList(), sel, "65.49.1.28")
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "exempt_source"


def test_dispatch_passes_through_non_exempt_source(tmp_path):
    p = tmp_path / "src.txt"
    p.write_text("65.49.1.16/28\n")
    sel = SourceExemptionList(p)
    q = _query("totally-innocent.example.com.")
    resp, handler = dispatch.dispatch(q, ExemptionList(), sel, "1.2.3.4")
    assert handler == "synth_a"


def test_source_exempt_beats_chaos_calling_card(tmp_path):
    """An exempt scanner must NOT receive the bind-chaos calling card."""
    p = tmp_path / "src.txt"
    p.write_text("65.49.1.16/28\n")
    sel = SourceExemptionList(p)
    q = dns.message.make_query(
        dns.name.from_text("version.bind."),
        dns.rdatatype.TXT,
        dns.rdataclass.CH,
    )
    resp, handler = dispatch.dispatch(q, ExemptionList(), sel, "65.49.1.28")
    assert resp.rcode() == dns.rcode.REFUSED
    assert handler == "exempt_source"


def test_dispatch_backward_compat_two_arg_call():
    """Existing call sites that pass only (query, exemptions) still work."""
    q = _query("example.com.")
    resp, handler = dispatch.dispatch(q, ExemptionList())
    assert handler == "synth_a"
    assert resp.rcode() == dns.rcode.NOERROR
