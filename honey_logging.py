"""Structured JSONL event logging for HoneyCow.

Shared by the DNS listeners and the HTTP catch-all closer. Every record
is one JSON object on its own line; the writer never raises into service
code (log failures are warned via the boot logger only).
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype

SCHEMA_VERSION = 1

log = logging.getLogger("honey_ns")


def now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def write_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON object per line. Logging must never crash service code."""
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        log.warning("log write failed: %s", exc)


def header_fields(query: dns.message.Message | None) -> dict[str, Any]:
    if query is None:
        return {}
    fields: dict[str, Any] = {
        "id": query.id,
        "opcode": dns.opcode.to_text(query.opcode()),
        "rcode": dns.rcode.to_text(query.rcode()),
        "flags": int(query.flags),
        "qdcount": len(query.question),
    }
    # EDNS OPT presence is signalled by edns >= 0. We capture the full
    # wire shape (header bits + per-option raw bytes hex-encoded) so
    # signatures we haven't dreamed up yet still have data to match
    # against. Readers decode specific option types as needed.
    if query.edns >= 0:
        try:
            fields["edns_version"] = int(query.edns)
            fields["edns_payload"] = int(query.payload)
            fields["edns_flags"] = int(query.ednsflags)
            fields["do_set"] = bool(query.ednsflags & dns.flags.DO)
            if query.options:
                fields["edns_options"] = sorted(int(o.otype) for o in query.options)
                opts_raw: list[dict[str, Any]] = []
                for o in query.options:
                    try:
                        wire = o.to_wire()
                    except (AttributeError, TypeError):
                        wire = b""
                    opts_raw.append(
                        {"otype": int(o.otype), "data_hex": wire.hex()},
                    )
                fields["edns_options_raw"] = opts_raw
        except (AttributeError, TypeError) as exc:
            log.debug("edns field extraction failed: %s", exc)
    return fields


def question_fields(query: dns.message.Message | None) -> dict[str, Any]:
    if query is None or not query.question:
        return {}
    question = query.question[0]
    return {
        "qname": question.name.to_text(),
        "qtype_name": dns.rdatatype.to_text(question.rdtype),
        "qtype_int": int(question.rdtype),
        "qclass_name": dns.rdataclass.to_text(question.rdclass),
        "qclass_int": int(question.rdclass),
    }


def response_fields(
    response: dns.message.Message | None,
    *,
    response_kind: str,
    response_bytes: int = 0,
    truncated: bool = False,
) -> dict[str, Any]:
    if response is None:
        return {
            "response_kind": response_kind,
            "response_bytes": response_bytes,
            "truncated": truncated,
        }
    return {
        "response_kind": response_kind,
        "rcode": dns.rcode.to_text(response.rcode()),
        "answer_count": sum(len(rrset) for rrset in response.answer),
        "authority_count": sum(len(rrset) for rrset in response.authority),
        "additional_count": sum(len(rrset) for rrset in response.additional),
        "response_bytes": response_bytes,
        "truncated": truncated,
    }


def event(
    *,
    event: str,
    request_id: str,
    transport: str,
    src_ip: str,
    src_port: int | None,
    dst_bind: str,
    raw_len: int,
    query: dns.message.Message | None = None,
    response: dns.message.Message | None = None,
    response_kind: str = "",
    response_bytes: int = 0,
    truncated: bool = False,
    handler: str = "",
    decision: str = "",
    drop_reason: str = "",
    rate_limited: bool = False,
    elapsed_ms: float | None = None,
    header: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "ts": now_iso(),
        "event": event,
        "request_id": request_id,
        "transport": transport,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_bind": dst_bind,
        "raw_len": raw_len,
        "handler": handler,
        "decision": decision,
        "drop_reason": drop_reason,
        "rate_limited": rate_limited,
    }
    if header:
        record.update(header)
    record.update(header_fields(query))
    record.update(question_fields(query))
    record.update(response_fields(
        response,
        response_kind=response_kind,
        response_bytes=response_bytes,
        truncated=truncated,
    ))
    if elapsed_ms is not None:
        record["elapsed_ms"] = round(elapsed_ms, 3)
    return record
