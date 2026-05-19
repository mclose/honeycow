"""Squatter dispatch — answer every query for every name (modulo exemption).

Decision tree:

  1. Exemption list -> REFUSED (operators of complaining zones get peace).
  2. Class check     -> IN or CH allowed, others REFUSED.
  3. AXFR / IXFR     -> REFUSED (regardless of class — we are not a real zone).
  4. Meta qtypes     -> FORMERR.
  5. CH class branch -> TXT returns calling card in CH class (the classic
     `version.bind` / `hostname.bind` / `id.server` / `authors.bind`
     fingerprint queries get the bluff); ANY returns RFC 8482 HINFO in CH;
     other CH qtypes return NOERROR / empty.
  6. IN class QTYPE switch:
       ANY     -> minimal RFC 8482 HINFO.
       A       -> synthesized A to sinkhole IP, NS in authority, glue in additional.
       AAAA    -> synthesized AAAA when sinkhole_aaaa is set, else NODATA.
       NS      -> synthesized NS at qname, glue in additional.
       SOA     -> synthesized SOA at qname, NS in authority, glue in additional.
       MX      -> synthesized MX -> ns1, plus A (and AAAA) for the MX target.
       TXT     -> calling-card TXT, NS in authority, glue in additional.
       other   -> NODATA with synthesized SOA at qname.

This is the full-bluff identity locked in project_honeycow_scoping.md.
"""

from __future__ import annotations

import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype

from squatter import base
from squatter.exemptions import ExemptionList

# Meta QTYPEs that are never valid in a question section (RFC 6895).
META_QTYPES = frozenset({
    dns.rdatatype.OPT,
    dns.rdatatype.TKEY,
    dns.rdatatype.TSIG,
    dns.rdatatype.MAILA,
    dns.rdatatype.MAILB,
})


def _attach_glue(response: dns.message.Message) -> None:
    """Append A (and AAAA, if v6 set) glue for every NS host."""
    for rrset in base.ns_glue_rrsets(
        base.TTL_NS, base.NS_HOSTS, base.PUBLIC_A, base.PUBLIC_AAAA,
    ):
        response.additional.append(rrset)


def _attach_authority_ns(
    response: dns.message.Message, zone_name: dns.name.Name,
) -> None:
    response.authority.append(
        base.synth_ns_rrset(zone_name, base.TTL_NS, base.NS_HOSTS)
    )


def dispatch(
    query: dns.message.Message, exemptions: ExemptionList,
) -> tuple[dns.message.Message, str]:
    """Route a parsed query through the full-bluff squatter.

    Returns (response, handler_name).
    """
    question = query.question[0]
    qname = question.name
    qtype = question.rdtype

    if exemptions.is_exempt(qname):
        return base.refused(query), "exempt"

    if question.rdclass not in (dns.rdataclass.IN, dns.rdataclass.CH):
        return base.refused(query), "refused_class"

    if qtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR):
        return base.refused(query), "refused_xfr"

    if qtype in META_QTYPES:
        return base.formerr(query), "formerr_meta_qtype"

    if question.rdclass == dns.rdataclass.CH:
        response = base.make_response(query)
        if qtype == dns.rdatatype.TXT:
            response.answer.append(
                base.synth_txt_rrset(
                    qname, base.TTL_TXT, base.TXT_CALLING_CARD,
                    rdclass=dns.rdataclass.CH,
                )
            )
            return response, "synth_txt_ch"
        if qtype == dns.rdatatype.ANY:
            response.answer.append(
                base.synth_hinfo_rrset(qname, rdclass=dns.rdataclass.CH)
            )
            return response, "minimal_any_hinfo_ch"
        # Any other CH qtype gets NOERROR / empty — no IN-class auth/glue
        # would make sense here, and CH-class SOA synthesis is more
        # surface-area than scanners actually probe.
        return response, "ch_nodata"

    if qtype == dns.rdatatype.ANY:
        response = base.make_response(query)
        response.answer.append(base.synth_hinfo_rrset(qname))
        return response, "minimal_any_hinfo"

    if qtype == dns.rdatatype.A:
        response = base.make_response(query)
        response.answer.append(
            base.synth_a_rrset(qname, base.TTL_SINKHOLE, base.SINKHOLE_A)
        )
        _attach_authority_ns(response, qname)
        _attach_glue(response)
        return response, "synth_a"

    if qtype == dns.rdatatype.AAAA:
        if not base.SINKHOLE_AAAA:
            return base.nodata(query), "nodata_no_v6"
        response = base.make_response(query)
        response.answer.append(
            base.synth_aaaa_rrset(qname, base.TTL_SINKHOLE, base.SINKHOLE_AAAA)
        )
        _attach_authority_ns(response, qname)
        _attach_glue(response)
        return response, "synth_aaaa"

    if qtype == dns.rdatatype.NS:
        response = base.make_response(query)
        response.answer.append(
            base.synth_ns_rrset(qname, base.TTL_NS, base.NS_HOSTS)
        )
        _attach_glue(response)
        return response, "synth_ns"

    if qtype == dns.rdatatype.SOA:
        response = base.make_response(query)
        response.answer.append(
            base.synth_soa_rrset(
                qname, base.TTL_SOA, base.NS_HOSTS[0], base.HOSTMASTER,
            )
        )
        _attach_authority_ns(response, qname)
        _attach_glue(response)
        return response, "synth_soa"

    if qtype == dns.rdatatype.MX:
        response = base.make_response(query)
        response.answer.append(
            base.synth_mx_rrset(qname, base.TTL_MX, base.NS_HOSTS[0])
        )
        response.additional.append(
            base.synth_a_rrset(base.NS_HOSTS[0], base.TTL_NS, base.PUBLIC_A)
        )
        if base.PUBLIC_AAAA:
            response.additional.append(
                base.synth_aaaa_rrset(
                    base.NS_HOSTS[0], base.TTL_NS, base.PUBLIC_AAAA,
                )
            )
        return response, "synth_mx"

    if qtype == dns.rdatatype.TXT:
        response = base.make_response(query)
        response.answer.append(
            base.synth_txt_rrset(qname, base.TTL_TXT, base.TXT_CALLING_CARD)
        )
        _attach_authority_ns(response, qname)
        _attach_glue(response)
        return response, "synth_txt"

    # Fallback: every other qtype is NODATA with a synthesized SOA at qname.
    return base.nodata(query), "nodata"
