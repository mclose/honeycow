"""Squatter identity, record synthesizers, response helpers, and serialization.

Honeycow has no fixed zone — every queried name is treated as its own zone
apex when SOA/NS are requested, and arbitrary records (A, AAAA, MX, TXT)
are synthesized regardless of where the name falls in the namespace.

Identity (domain, NS hostnames, abuse contact, TXT calling-card, public
and sinkhole IPs) is read from HONEY_* env at import. main() in
honey_ns.py validates HONEY_PUBLIC_A before binding sockets.
"""

from __future__ import annotations

import os

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.HINFO
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rrset

# ---------------------------------------------------------------------------
# Identity (env-configurable)
# ---------------------------------------------------------------------------

_DEFAULT_DOMAIN = "example.com."
_DEFAULT_NS_HOSTS = "ns1.example.com,ns2.example.com"
_DEFAULT_ABUSE_EMAIL = "abuse@example.com"
_DEFAULT_ABUSE_URL = "https://example.com"
_DEFAULT_TXT_CALLING_CARD = (
    "honeycow: this is not the cow you are looking for. "
    "a polite ns squatter. https://example.com abuse@example.com"
)

DOMAIN = dns.name.from_text(os.environ.get("HONEY_DOMAIN", _DEFAULT_DOMAIN))


def _parse_ns_hosts(raw: str) -> list[dns.name.Name]:
    hosts: list[dns.name.Name] = []
    for token in raw.split(","):
        text = token.strip()
        if not text:
            continue
        if not text.endswith("."):
            text += "."
        hosts.append(dns.name.from_text(text))
    if not hosts:
        raise ValueError("HONEY_NS_HOSTS resolves to an empty list")
    return hosts


NS_HOSTS = _parse_ns_hosts(os.environ.get("HONEY_NS_HOSTS", _DEFAULT_NS_HOSTS))

_ABUSE_EMAIL = os.environ.get("HONEY_ABUSE_EMAIL", _DEFAULT_ABUSE_EMAIL)


def _email_to_rname(email: str) -> dns.name.Name:
    """abuse@example.com -> abuse.example.com. for use as SOA RNAME.

    Local-parts containing dots would need DNS escaping; the simple form
    used by typical abuse contacts does not. A dotted local-part will
    produce a slightly wrong RNAME on the wire.
    """
    local, _, domain = email.partition("@")
    if not local or not domain:
        raise ValueError(f"invalid HONEY_ABUSE_EMAIL: {email!r}")
    return dns.name.from_text(f"{local}.{domain}.")


HOSTMASTER = _email_to_rname(_ABUSE_EMAIL)
ABUSE_URL = os.environ.get("HONEY_ABUSE_URL", _DEFAULT_ABUSE_URL)
TXT_CALLING_CARD = os.environ.get(
    "HONEY_TXT_CALLING_CARD",
    _DEFAULT_TXT_CALLING_CARD,
)

# Public addresses of the honeycow VPS. PUBLIC_A is required at runtime
# (honey_ns.main validates it); the loopback default keeps test imports
# clean.
PUBLIC_A = os.environ.get("HONEY_PUBLIC_A", "127.0.0.1")
PUBLIC_AAAA = os.environ.get("HONEY_PUBLIC_AAAA", "")

# Sinkhole target — what synthesized A/AAAA answers point at. Defaults to
# the public address so followup connections loop back and get logged.
SINKHOLE_A = os.environ.get("HONEY_SINKHOLE_A", "") or PUBLIC_A
SINKHOLE_AAAA = os.environ.get("HONEY_SINKHOLE_AAAA", "") or PUBLIC_AAAA

# TTLs (seconds).
TTL_SINKHOLE = 300
TTL_TXT = 300
TTL_MX = 300
TTL_NS = 3600
TTL_SOA = 3600
TTL_NEGATIVE = 300

SOA_SERIAL = 2026051801
SOA_REFRESH = 3600
SOA_RETRY = 900
SOA_EXPIRE = 604800

UDP_MAX = 512
TCP_MAX = 65535

TXT_CHUNK_LIMIT = 255  # RFC 1035 character-string max


# ---------------------------------------------------------------------------
# Synthesizers
# ---------------------------------------------------------------------------

def synth_a_rrset(name: dns.name.Name, ttl: int, addr: str) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.A)
    rrset.add(dns.rdtypes.IN.A.A(dns.rdataclass.IN, dns.rdatatype.A, addr), ttl)
    return rrset


def synth_aaaa_rrset(name: dns.name.Name, ttl: int, addr: str) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.AAAA)
    rrset.add(
        dns.rdtypes.IN.AAAA.AAAA(dns.rdataclass.IN, dns.rdatatype.AAAA, addr),
        ttl,
    )
    return rrset


def synth_ns_rrset(
    zone_name: dns.name.Name, ttl: int, ns_hosts: list[dns.name.Name],
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.NS)
    for ns_host in ns_hosts:
        rrset.add(
            dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, ns_host),
            ttl,
        )
    return rrset


def synth_soa_rrset(
    zone_name: dns.name.Name,
    ttl: int,
    mname: dns.name.Name,
    rname: dns.name.Name,
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.SOA)
    rrset.add(
        dns.rdtypes.ANY.SOA.SOA(
            dns.rdataclass.IN,
            dns.rdatatype.SOA,
            mname=mname,
            rname=rname,
            serial=SOA_SERIAL,
            refresh=SOA_REFRESH,
            retry=SOA_RETRY,
            expire=SOA_EXPIRE,
            minimum=TTL_NEGATIVE,
        ),
        ttl,
    )
    return rrset


def synth_mx_rrset(
    name: dns.name.Name,
    ttl: int,
    exchange: dns.name.Name,
    preference: int = 10,
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.MX)
    rrset.add(
        dns.rdtypes.ANY.MX.MX(
            dns.rdataclass.IN, dns.rdatatype.MX, preference, exchange,
        ),
        ttl,
    )
    return rrset


def synth_txt_rrset(name: dns.name.Name, ttl: int, text: str) -> dns.rrset.RRset:
    encoded = text.encode("utf-8")
    if len(encoded) > TXT_CHUNK_LIMIT:
        chunks = [
            encoded[i:i + TXT_CHUNK_LIMIT]
            for i in range(0, len(encoded), TXT_CHUNK_LIMIT)
        ]
    else:
        chunks = [encoded]
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.TXT)
    rrset.add(
        dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, dns.rdatatype.TXT, chunks),
        ttl,
    )
    return rrset


def synth_hinfo_rrset(
    name: dns.name.Name, ttl: int = TTL_NEGATIVE,
) -> dns.rrset.RRset:
    """RFC 8482 minimal ANY response."""
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.HINFO)
    rrset.add(
        dns.rdtypes.ANY.HINFO.HINFO(
            dns.rdataclass.IN,
            dns.rdatatype.HINFO,
            b"RFC8482",
            b"",
        ),
        ttl,
    )
    return rrset


def ns_glue_rrsets(
    ttl: int,
    ns_hosts: list[dns.name.Name],
    a_addr: str,
    aaaa_addr: str,
) -> list[dns.rrset.RRset]:
    """A + AAAA glue for each NS host. AAAA is omitted when aaaa_addr is empty."""
    rrsets: list[dns.rrset.RRset] = []
    for ns_host in ns_hosts:
        rrsets.append(synth_a_rrset(ns_host, ttl, a_addr))
        if aaaa_addr:
            rrsets.append(synth_aaaa_rrset(ns_host, ttl, aaaa_addr))
    return rrsets


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

def make_response(query: dns.message.Message) -> dns.message.Message:
    """Base authoritative response shell. AA set, RA cleared, EDNS stripped."""
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    response.flags &= ~dns.flags.RA
    response.use_edns(False)
    return response


def negative_response(
    query: dns.message.Message,
    rcode: int,
    zone_name: dns.name.Name | None = None,
) -> dns.message.Message:
    """NXDOMAIN / NODATA with synthesized SOA in authority.

    The squatter has no fixed zone, so the SOA owner defaults to qname.
    """
    response = make_response(query)
    response.set_rcode(rcode)
    if zone_name is None:
        zone_name = query.question[0].name
    response.authority.append(
        synth_soa_rrset(zone_name, TTL_SOA, NS_HOSTS[0], HOSTMASTER)
    )
    return response


def nodata(query: dns.message.Message) -> dns.message.Message:
    return negative_response(query, dns.rcode.NOERROR)


def _error_response(query: dns.message.Message, rcode: int) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.flags &= ~dns.flags.AA
    response.flags &= ~dns.flags.RA
    response.use_edns(False)
    response.set_rcode(rcode)
    return response


def servfail(query: dns.message.Message) -> dns.message.Message:
    return _error_response(query, dns.rcode.SERVFAIL)


def notimp(query: dns.message.Message) -> dns.message.Message:
    return _error_response(query, dns.rcode.NOTIMP)


def refused(query: dns.message.Message) -> dns.message.Message:
    return _error_response(query, dns.rcode.REFUSED)


def formerr(query: dns.message.Message) -> dns.message.Message:
    return _error_response(query, dns.rcode.FORMERR)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def serialize_udp(response: dns.message.Message) -> tuple[bytes, bool]:
    """Serialize for UDP; set TC and truncate if > 512 bytes."""
    try:
        wire = response.to_wire(max_size=UDP_MAX)
        return wire, False
    except dns.exception.TooBig:
        response.answer = []
        response.authority = []
        response.additional = []
        response.flags |= dns.flags.TC
        return response.to_wire(max_size=UDP_MAX), True


def serialize_tcp(response: dns.message.Message) -> bytes:
    return response.to_wire(max_size=TCP_MAX)
