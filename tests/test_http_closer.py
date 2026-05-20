"""Tests for honey_http XFF parsing, client-IP resolution, and templating."""

from __future__ import annotations

import pytest

import honey_http
from honey_http import _parse_request, _resolve_client_ip


def test_parse_request_extracts_xff():
    raw = (
        b"GET /probe HTTP/1.1\r\n"
        b"Host: scanner.test\r\n"
        b"User-Agent: curl/8\r\n"
        b"X-Forwarded-For: 203.0.113.7\r\n"
        b"\r\n"
    )
    method, path, host, ua, xff = _parse_request(raw)
    assert method == "GET"
    assert path == "/probe"
    assert host == "scanner.test"
    assert ua == "curl/8"
    assert xff == "203.0.113.7"


def test_parse_request_no_xff_returns_empty():
    raw = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    _, _, _, _, xff = _parse_request(raw)
    assert xff == ""


@pytest.mark.parametrize("peer", ["172.18.0.4", "10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "fd00::1"])
def test_resolve_client_ip_trusts_xff_from_private_peer(peer):
    assert _resolve_client_ip(peer, "203.0.113.7") == "203.0.113.7"


@pytest.mark.parametrize("peer", ["8.8.8.8", "2606:4700:4700::1111", "76.13.112.47"])
def test_resolve_client_ip_ignores_xff_from_public_peer(peer):
    # A direct hit on the closer (bypassing Caddy) must not let the client
    # rewrite their own logged IP via XFF.
    assert _resolve_client_ip(peer, "203.0.113.7") == peer


def test_resolve_client_ip_takes_rightmost_xff_entry():
    # Caddy appends to existing XFF. Anything left of the rightmost entry
    # was supplied by the client and is untrusted.
    assert _resolve_client_ip("172.18.0.4", "8.8.8.8, 203.0.113.7") == "203.0.113.7"


def test_resolve_client_ip_falls_back_on_garbage_xff():
    assert _resolve_client_ip("172.18.0.4", "not-an-ip") == "172.18.0.4"


def test_resolve_client_ip_no_xff_returns_peer():
    assert _resolve_client_ip("172.18.0.4", "") == "172.18.0.4"


def test_resolve_client_ip_handles_ipv6_xff():
    assert _resolve_client_ip("172.18.0.4", "2001:db8::42") == "2001:db8::42"


# --- cowsay rendering + body templating ----------------------------------

def test_cowsay_two_lines_pads_to_max_width():
    rendered = honey_http._cowsay(["Welcome to the pasture!", "1.2.3.4"])
    lines = rendered.split("\n")

    # 4 header/footer lines + 5 cow lines = 9 total.
    assert len(lines) == 9

    # Longer line ("Welcome to the pasture!" = 23 chars) sets the internal
    # bubble width; the IP line gets right-padded to match.
    assert lines[0] == " " + "_" * 25
    assert lines[1] == "/ Welcome to the pasture! \\"
    assert lines[2] == "\\ 1.2.3.4                 /"
    assert lines[3] == " " + "-" * 25
    # And the cow itself is constant.
    assert lines[4] == "        \\   ^__^"
    assert lines[5] == "         \\  (oo)\\_______"


def test_cowsay_widens_for_long_ipv6():
    long_ip = "2604:a880:800:14:0:2:f83c:0"  # 27 chars, longer than welcome
    rendered = honey_http._cowsay(["Welcome to the pasture!", long_ip])
    lines = rendered.split("\n")
    # Width should now be 27 (IP line), not 23 (welcome line).
    assert lines[0] == " " + "_" * 29
    # The welcome message gets padded to width=27.
    assert lines[1] == "/ Welcome to the pasture!     \\"
    assert lines[2] == f"\\ {long_ip} /"


def test_render_body_substitutes_cowsay_and_client_ip():
    template = (
        b"<html><body>"
        b"<p>Your IP is {client_ip}.</p>"
        b"<pre>{cowsay_block}</pre>"
        b"</body></html>"
    )
    rendered = honey_http.render_body(template, "203.0.113.5")
    assert b"Your IP is 203.0.113.5." in rendered
    assert b"Welcome to the pasture!" in rendered
    assert b"^__^" in rendered
    assert b"{client_ip}" not in rendered
    assert b"{cowsay_block}" not in rendered
