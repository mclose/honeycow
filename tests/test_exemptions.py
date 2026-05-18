"""Exemption-list loader behavior."""

from __future__ import annotations

import dns.name

from squatter.exemptions import ExemptionList


def test_empty_list_matches_nothing():
    el = ExemptionList()
    assert not el.is_exempt(dns.name.from_text("anywhere.tld."))


def test_loads_one_per_line(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\nblocked.org\n")
    el = ExemptionList(p)
    assert len(el) == 2
    assert el.is_exempt(dns.name.from_text("example.com."))
    assert el.is_exempt(dns.name.from_text("blocked.org."))


def test_matches_subdomain(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    assert el.is_exempt(dns.name.from_text("foo.example.com."))
    assert el.is_exempt(dns.name.from_text("a.b.c.example.com."))


def test_does_not_match_sibling(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    assert not el.is_exempt(dns.name.from_text("example.org."))
    assert not el.is_exempt(dns.name.from_text("notexample.com."))


def test_ignores_comments_and_blanks(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("# top\nexample.com  # inline\n\n  \nblocked.org\n")
    el = ExemptionList(p)
    assert len(el) == 2


def test_reload_picks_up_changes(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    assert el.is_exempt(dns.name.from_text("example.com."))

    p.write_text("other.tld\n")
    el.load()
    assert not el.is_exempt(dns.name.from_text("example.com."))
    assert el.is_exempt(dns.name.from_text("other.tld."))


def test_parse_failure_keeps_old_list(tmp_path):
    p = tmp_path / "ex.txt"
    p.write_text("example.com\n")
    el = ExemptionList(p)
    # Empty label between dots is a DNSException -> bad parse.
    p.write_text("foo..bar\n")
    el.load()
    assert el.is_exempt(dns.name.from_text("example.com."))
