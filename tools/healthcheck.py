#!/usr/bin/env python3
"""DNS-native container healthcheck for honeycow.

Sends a SOA query for the identity domain to the local DNS port. Since
honeycow synthesizes a response for any name, success here just confirms
parser + dispatch + socket bind are all up.
"""

from __future__ import annotations

import os
import socket
import sys

import dns.message
import dns.name
import dns.rcode
import dns.rdatatype


def main() -> int:
    name = dns.name.from_text(os.environ.get("HONEY_DOMAIN", "honeycow.net."))
    port = int(os.environ.get("HONEY_PORT", "53"))
    query = dns.message.make_query(name, dns.rdatatype.SOA)
    wire = query.to_wire()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.sendto(wire, ("127.0.0.1", port))
        response_wire, _ = sock.recvfrom(512)

    response = dns.message.from_wire(response_wire)
    if response.id != query.id:
        return 1
    if response.rcode() != dns.rcode.NOERROR:
        return 1
    if not any(rrset.rdtype == dns.rdatatype.SOA for rrset in response.answer):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
