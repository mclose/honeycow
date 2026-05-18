"""HoneyCow — full-bluff NS-squatting DNS server plus HTTP catch-all closer.

Answers every query for every zone with synthesized records pointing at
the configured sinkhole address (default: this server's own IP). A
catch-all HTTP server on the configured HTTP port returns a fixed
explanation page to scanners who follow the DNS bluff.

Single asyncio process. UDP datagram endpoint + TCP server on the DNS
port, plus TCP server on the HTTP port. Trust-nothing wire validation
on the DNS side.

Run directly for local testing:

    HONEY_PORT=15353 HONEY_HTTP_PORT=18080 HONEY_PUBLIC_A=127.0.0.1 \\
        HONEY_LOG=/tmp/honeycow.jsonl python honey_ns.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import struct
import sys
import time
import uuid
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype

import honey_http
import honey_logging
from squatter import base, dispatch
from squatter.exemptions import ExemptionList

DEFAULT_PORT = 53
DEFAULT_HTTP_PORT = 80
DEFAULT_BIND_V4 = "0.0.0.0"
DEFAULT_BIND_V6 = "::"
DEFAULT_LOG_PATH = "/var/log/honeycow/events.jsonl"
DEFAULT_EXEMPTION_PATH = "/etc/honeycow/exemptions.txt"
DEFAULT_STATIC_PATH = "/app/static/index.html"
DEFAULT_TCP_TIMEOUT = 5.0
DEFAULT_TCP_MAX_CONNS = 50
DEFAULT_TCP_ACCEPT_BACKLOG = 100
DEFAULT_TCP_MAX_QUERIES_PER_CONN = 32
DEFAULT_UDP_RATELIMIT_RATE = 200.0
DEFAULT_UDP_RATELIMIT_BURST = 400
TCP_LENGTH_PREFIX = 2
TCP_QUERY_MAX_BYTES = 4096
UDP_MAX = base.UDP_MAX

LOG_PATH: Path = Path(DEFAULT_LOG_PATH)
EXEMPTIONS: ExemptionList = ExemptionList()

log = logging.getLogger("honey_ns")


# ---------------------------------------------------------------------------
# Wire-format handling
# ---------------------------------------------------------------------------

def _log_event(record: dict) -> None:
    honey_logging.write_jsonl(LOG_PATH, record)


def _request_id() -> str:
    return uuid.uuid4().hex


def _peer_port(addr: tuple | None) -> int | None:
    if not addr or len(addr) < 2:
        return None
    return int(addr[1])


def _bind_text(sockname: tuple | None) -> str:
    if not sockname:
        return ""
    if len(sockname) >= 2:
        return f"{sockname[0]}:{sockname[1]}"
    return str(sockname)


def _wire_header(data: bytes) -> dict | None:
    if len(data) < 12:
        return None
    msg_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
    opcode = (flags >> 11) & 0x0F
    return {
        "id": msg_id,
        "opcode": dns.opcode.to_text(opcode),
        "rcode": dns.rcode.to_text(flags & 0x0F),
        "flags": flags,
        "qdcount": qdcount,
    }


def _minimal_formerr(data: bytes) -> tuple[bytes, dns.message.Message | None]:
    header = _wire_header(data)
    if header is None:
        return b"", None
    response = dns.message.Message(id=header["id"])
    original_flags = int(header["flags"])
    opcode_bits = original_flags & 0x7800
    rd_bit = original_flags & dns.flags.RD
    response.flags = dns.flags.QR | opcode_bits | rd_bit
    response.set_rcode(dns.rcode.FORMERR)
    return response.to_wire(max_size=UDP_MAX), response


def _serialize(response: dns.message.Message, transport: str) -> tuple[bytes, bool]:
    if transport == "udp":
        return base.serialize_udp(response)
    return base.serialize_tcp(response), False


def handle_wire(data: bytes, transport: str) -> tuple[
    bytes, str, bool,
    dns.message.Message | None, dns.message.Message | None,
    str,
]:
    """Parse, dispatch, and serialize one query.

    Returns (wire_bytes, response_kind, truncated, query, response, handler).
    """
    try:
        query = dns.message.from_wire(data)
    except dns.exception.DNSException as exc:
        wire, response = _minimal_formerr(data)
        return (
            wire,
            f"FORMERR ({type(exc).__name__})",
            False,
            None,
            response,
            "parse_error",
        )

    if query.flags & dns.flags.QR:
        return b"", "DROPPED_QR", False, None, None, "qr_set"

    if query.opcode() != dns.opcode.QUERY:
        response = base.notimp(query)
        wire, truncated = _serialize(response, transport)
        return wire, "NOTIMP", truncated, query, response, "bad_opcode"

    if len(query.question) != 1:
        response = base.make_response(query)
        response.set_rcode(dns.rcode.FORMERR)
        wire, truncated = _serialize(response, transport)
        return wire, "FORMERR", truncated, query, response, "bad_qcount"

    try:
        response, handler_name = dispatch.dispatch(query, EXEMPTIONS)
        wire, truncated = _serialize(response, transport)
    except Exception:  # pragma: no cover — defense in depth
        log.exception("dispatch crashed")
        response = base.servfail(query)
        wire, truncated = _serialize(response, transport)
        return wire, "SERVFAIL", truncated, query, response, "handler_crash"

    return (
        wire, dns.rcode.to_text(response.rcode()),
        truncated, query, response, handler_name,
    )


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Small in-process token bucket keyed by source IP and response class."""

    def __init__(self, rate: float, burst: int, enabled: bool = True) -> None:
        self.rate = rate
        self.burst = burst
        self.enabled = enabled
        self._buckets: dict[tuple[str, str], tuple[float, float]] = {}

    def allow(self, src_ip: str, response_class: str) -> bool:
        if not self.enabled or self.rate <= 0 or self.burst <= 0:
            return True
        now = time.monotonic()
        key = (src_ip, response_class)
        tokens, updated = self._buckets.get(key, (float(self.burst), now))
        tokens = min(float(self.burst), tokens + (now - updated) * self.rate)
        if tokens < 1:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1, now)
        return True


class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, rate_limiter: TokenBucketRateLimiter | None = None) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter(
            DEFAULT_UDP_RATELIMIT_RATE, DEFAULT_UDP_RATELIMIT_BURST,
        )

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple) -> None:  # type: ignore[override]
        src_ip = addr[0]
        src_port = _peer_port(addr)
        request_id = _request_id()
        start = time.monotonic()
        sockname = None
        if self.transport is not None:
            sockname = self.transport.get_extra_info("sockname")
        dst_bind = _bind_text(sockname)

        if len(data) > UDP_MAX:
            _log_event(honey_logging.event(
                event="query_drop",
                request_id=request_id,
                transport="udp",
                src_ip=src_ip,
                src_port=src_port,
                dst_bind=dst_bind,
                raw_len=len(data),
                response_kind="DROPPED",
                decision="drop",
                drop_reason="oversized_datagram",
                elapsed_ms=(time.monotonic() - start) * 1000,
            ))
            return

        wire, kind, truncated, query, response, handler = handle_wire(data, "udp")
        if not wire:
            _log_event(honey_logging.event(
                event="query_drop",
                request_id=request_id,
                transport="udp",
                src_ip=src_ip,
                src_port=src_port,
                dst_bind=dst_bind,
                raw_len=len(data),
                query=query,
                response=response,
                response_kind=kind,
                handler=handler,
                decision="drop",
                drop_reason=kind,
                elapsed_ms=(time.monotonic() - start) * 1000,
                header=_wire_header(data),
            ))
            return

        if not self.rate_limiter.allow(src_ip, kind):
            _log_event(honey_logging.event(
                event="query_drop",
                request_id=request_id,
                transport="udp",
                src_ip=src_ip,
                src_port=src_port,
                dst_bind=dst_bind,
                raw_len=len(data),
                query=query,
                response=response,
                response_kind=kind,
                response_bytes=len(wire),
                truncated=truncated,
                handler=handler,
                decision="drop",
                drop_reason="rate_limited",
                rate_limited=True,
                elapsed_ms=(time.monotonic() - start) * 1000,
            ))
            return

        elapsed_ms = (time.monotonic() - start) * 1000
        assert self.transport is not None
        self.transport.sendto(wire, addr)
        _log_event(honey_logging.event(
            event="query",
            request_id=request_id,
            transport="udp",
            src_ip=src_ip,
            src_port=src_port,
            dst_bind=dst_bind,
            raw_len=len(data),
            query=query,
            response=response,
            response_kind=kind,
            response_bytes=len(wire),
            truncated=truncated,
            handler=handler,
            decision="respond",
            elapsed_ms=elapsed_ms,
            header=_wire_header(data),
        ))


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

async def handle_tcp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    timeout: float,
    max_queries_per_conn: int,
) -> None:
    peer = writer.get_extra_info("peername") or ("?", 0)
    src_ip = peer[0] if peer else "?"
    src_port = _peer_port(peer)
    dst_bind = _bind_text(writer.get_extra_info("sockname"))
    responses_sent = 0

    try:
        for _ in range(max(1, max_queries_per_conn)):
            request_id = _request_id()
            start = time.monotonic()
            try:
                prefix = await asyncio.wait_for(
                    reader.readexactly(TCP_LENGTH_PREFIX), timeout=timeout,
                )
                length = int.from_bytes(prefix, "big")
                if length == 0 or length > TCP_QUERY_MAX_BYTES:
                    _log_event(honey_logging.event(
                        event="query_drop",
                        request_id=request_id,
                        transport="tcp",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_bind=dst_bind,
                        raw_len=length,
                        response_kind="DROPPED",
                        decision="drop",
                        drop_reason=f"bad_length_prefix={length}",
                        elapsed_ms=(time.monotonic() - start) * 1000,
                    ))
                    return
                data = await asyncio.wait_for(
                    reader.readexactly(length), timeout=timeout,
                )
            except TimeoutError as exc:
                if responses_sent > 0:
                    return
                _log_event(honey_logging.event(
                    event="query_drop",
                    request_id=request_id,
                    transport="tcp",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_bind=dst_bind,
                    raw_len=0,
                    response_kind="DROPPED",
                    decision="drop",
                    drop_reason=f"read_failed:{type(exc).__name__}",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                return
            except asyncio.IncompleteReadError as exc:
                if exc.partial == b"":
                    return
                _log_event(honey_logging.event(
                    event="query_drop",
                    request_id=request_id,
                    transport="tcp",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_bind=dst_bind,
                    raw_len=len(exc.partial),
                    response_kind="DROPPED",
                    decision="drop",
                    drop_reason=f"read_failed:{type(exc).__name__}",
                    elapsed_ms=(time.monotonic() - start) * 1000,
                ))
                return

            wire, kind, truncated, query, response, handler = handle_wire(data, "tcp")
            if not wire:
                _log_event(honey_logging.event(
                    event="query_drop",
                    request_id=request_id,
                    transport="tcp",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_bind=dst_bind,
                    raw_len=len(data),
                    query=query,
                    response=response,
                    response_kind=kind,
                    handler=handler,
                    decision="drop",
                    drop_reason=kind,
                    elapsed_ms=(time.monotonic() - start) * 1000,
                    header=_wire_header(data),
                ))
                return

            try:
                writer.write(len(wire).to_bytes(TCP_LENGTH_PREFIX, "big"))
                writer.write(wire)
                await writer.drain()
            except OSError as exc:
                log.warning("tcp write failed: %s", exc)
                return
            responses_sent += 1

            _log_event(honey_logging.event(
                event="query",
                request_id=request_id,
                transport="tcp",
                src_ip=src_ip,
                src_port=src_port,
                dst_bind=dst_bind,
                raw_len=len(data),
                query=query,
                response=response,
                response_kind=kind,
                response_bytes=len(wire),
                truncated=truncated,
                handler=handler,
                decision="respond",
                elapsed_ms=(time.monotonic() - start) * 1000,
                header=_wire_header(data),
            ))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

async def serve(
    bind_v4: str, bind_v6: str, port: int, http_port: int,
    timeout: float, max_conns: int, accept_backlog: int,
    max_queries_per_conn: int,
    udp_rate_limiter: TokenBucketRateLimiter,
    static_path: Path,
) -> None:
    loop = asyncio.get_running_loop()

    udp_transports: list[asyncio.DatagramTransport] = []
    udp_v4, _ = await loop.create_datagram_endpoint(
        lambda: UDPProtocol(udp_rate_limiter),
        local_addr=(bind_v4, port),
        reuse_port=False,
    )
    udp_transports.append(udp_v4)
    log.info("UDP listening on %s:%d", bind_v4, port)

    if bind_v6:
        # Explicit V6ONLY=1 so the v6 datagram socket doesn't collide with
        # the v4 0.0.0.0 bind above. asyncio.start_server sets V6ONLY for
        # TCP automatically; create_datagram_endpoint does not.
        v6_udp_sock: socket.socket | None = None
        try:
            v6_udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            v6_udp_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            v6_udp_sock.bind((bind_v6, port))
            udp_v6, _ = await loop.create_datagram_endpoint(
                lambda: UDPProtocol(udp_rate_limiter),
                sock=v6_udp_sock,
            )
            udp_transports.append(udp_v6)
            log.info("UDP listening on [%s]:%d", bind_v6, port)
        except OSError as exc:
            if v6_udp_sock is not None:
                v6_udp_sock.close()
            log.warning("IPv6 UDP bind failed: %s", exc)

    sem = asyncio.Semaphore(max_conns)

    async def tcp_dispatch(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        if sem.locked():
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
            return
        async with sem:
            await handle_tcp(reader, writer, timeout, max_queries_per_conn)

    tcp_servers: list[asyncio.AbstractServer] = []
    tcp_v4 = await asyncio.start_server(
        tcp_dispatch, bind_v4, port, backlog=accept_backlog,
    )
    tcp_servers.append(tcp_v4)
    log.info("TCP listening on %s:%d", bind_v4, port)

    if bind_v6:
        try:
            tcp_v6 = await asyncio.start_server(
                tcp_dispatch, bind_v6, port, backlog=accept_backlog,
            )
            tcp_servers.append(tcp_v6)
            log.info("TCP listening on [%s]:%d", bind_v6, port)
        except OSError as exc:
            log.warning("IPv6 TCP bind failed: %s", exc)

    http_servers: list[asyncio.AbstractServer] = []
    if http_port > 0:
        body = honey_http.load_body(static_path)
        try:
            http_servers = await honey_http.serve(
                bind_v4, bind_v6, http_port, body, LOG_PATH,
            )
        except OSError as exc:
            log.warning("HTTP bind failed on port %d: %s", http_port, exc)

    all_servers = tcp_servers + http_servers
    try:
        await asyncio.gather(*(s.serve_forever() for s in all_servers))
    except asyncio.CancelledError:
        log.info("shutting down")
        for transport in udp_transports:
            transport.close()
        for server in all_servers:
            server.close()
            await server.wait_closed()


def _load_config() -> dict:
    return {
        "bind_v4": os.environ.get("HONEY_BIND_V4", DEFAULT_BIND_V4),
        "bind_v6": os.environ.get("HONEY_BIND_V6", DEFAULT_BIND_V6),
        "port": int(os.environ.get("HONEY_PORT", DEFAULT_PORT)),
        "http_port": int(os.environ.get("HONEY_HTTP_PORT", DEFAULT_HTTP_PORT)),
        "timeout": float(os.environ.get("HONEY_TCP_TIMEOUT", DEFAULT_TCP_TIMEOUT)),
        "max_conns": int(os.environ.get(
            "HONEY_TCP_MAX_CONNS", DEFAULT_TCP_MAX_CONNS,
        )),
        "accept_backlog": int(os.environ.get(
            "HONEY_TCP_ACCEPT_BACKLOG", DEFAULT_TCP_ACCEPT_BACKLOG,
        )),
        "max_queries_per_conn": int(os.environ.get(
            "HONEY_TCP_MAX_QUERIES_PER_CONN", DEFAULT_TCP_MAX_QUERIES_PER_CONN,
        )),
        "udp_ratelimit_enabled": os.environ.get(
            "HONEY_UDP_RATELIMIT_ENABLED", "1",
        ).lower() not in {"0", "false", "no"},
        "udp_ratelimit_rate": float(os.environ.get(
            "HONEY_UDP_RATELIMIT_RATE", DEFAULT_UDP_RATELIMIT_RATE,
        )),
        "udp_ratelimit_burst": int(os.environ.get(
            "HONEY_UDP_RATELIMIT_BURST", DEFAULT_UDP_RATELIMIT_BURST,
        )),
        "log_path": os.environ.get("HONEY_LOG", DEFAULT_LOG_PATH),
        "exemption_path": os.environ.get(
            "HONEY_EXEMPTION_FILE", DEFAULT_EXEMPTION_PATH,
        ),
        "static_path": os.environ.get("HONEY_STATIC_INDEX", DEFAULT_STATIC_PATH),
    }


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)r}',
    )

    if "HONEY_PUBLIC_A" not in os.environ:
        log.error(
            "HONEY_PUBLIC_A is required (public IPv4 of this VPS; used as "
            "NS glue and default sinkhole target)."
        )
        return 1

    cfg = _load_config()

    global LOG_PATH, EXEMPTIONS
    LOG_PATH = Path(cfg["log_path"])
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    exemption_path = Path(cfg["exemption_path"])
    if exemption_path.is_file():
        EXEMPTIONS = ExemptionList(exemption_path)
    else:
        log.info(
            "no exemption file at %s — running with empty list",
            exemption_path,
        )
        EXEMPTIONS = ExemptionList()

    log.info(
        "squatting as %s (NS=%s, sinkhole_a=%s sinkhole_aaaa=%s)",
        base.DOMAIN.to_text(),
        ",".join(h.to_text() for h in base.NS_HOSTS),
        base.SINKHOLE_A,
        base.SINKHOLE_AAAA or "(none)",
    )
    log.info("event log: %s", LOG_PATH)
    log.info("exemptions: %d entries from %s", len(EXEMPTIONS), exemption_path)
    log.info(
        "udp rate limit: enabled=%s rate=%s burst=%s",
        cfg["udp_ratelimit_enabled"],
        cfg["udp_ratelimit_rate"],
        cfg["udp_ratelimit_burst"],
    )

    udp_rate_limiter = TokenBucketRateLimiter(
        cfg["udp_ratelimit_rate"],
        cfg["udp_ratelimit_burst"],
        cfg["udp_ratelimit_enabled"],
    )

    loop = asyncio.new_event_loop()
    serve_task = loop.create_task(serve(
        cfg["bind_v4"], cfg["bind_v6"], cfg["port"], cfg["http_port"],
        cfg["timeout"], cfg["max_conns"], cfg["accept_backlog"],
        cfg["max_queries_per_conn"], udp_rate_limiter,
        Path(cfg["static_path"]),
    ))

    def _shutdown() -> None:
        log.info("signal received, cancelling")
        serve_task.cancel()

    def _sighup() -> None:
        if EXEMPTIONS.path is not None:
            log.info("SIGHUP received, reloading exemptions")
            EXEMPTIONS.load()
        else:
            log.info("SIGHUP received, no exemption file configured — ignored")

    loop.add_signal_handler(signal.SIGTERM, _shutdown)
    loop.add_signal_handler(signal.SIGINT, _shutdown)
    loop.add_signal_handler(signal.SIGHUP, _sighup)

    try:
        loop.run_until_complete(serve_task)
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
