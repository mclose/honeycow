"""Tests for honey_http XFF parsing and client-IP resolution."""

from __future__ import annotations

import pytest

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
