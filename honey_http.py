"""Catch-all HTTP closer for the honeycow VPS.

Every connection — any Host header, any path — gets the same explanation
page back. Scanners who follow the DNS bluff (where every A record points
at this server's IP) hit this instead of a refused connection.

Lives in the same asyncio process as honey_ns.py. Reads the static page
at startup; if unreadable, serves a minimal hard-coded fallback.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

import honey_logging

log = logging.getLogger("honey_ns")

_FALLBACK_BODY = (
    "<!doctype html><html><head>"
    "<title>honeycow</title>"
    "</head><body>"
    "<h1>honeycow</h1>"
    "<p>this is not the cow you are looking for.</p>"
    "<p>a polite ns squatter. contact: abuse@honeycow.net</p>"
    "</body></html>"
)

# How many request bytes to read before giving up. We only need the request
# line + headers to log; the body is irrelevant.
_HTTP_READ_MAX = 8192
_HTTP_READ_TIMEOUT = 5.0


def load_body(static_path: Path) -> bytes:
    try:
        return static_path.read_bytes()
    except OSError as exc:
        log.warning("static index unreadable (%s), using fallback", exc)
        return _FALLBACK_BODY.encode("utf-8")


def _parse_request(data: bytes) -> tuple[str, str, str, str]:
    """Pull method, path, Host, and User-Agent from a request prefix.

    All fields are best-effort and never raise — the closer logs whatever
    it can see and serves the same body either way.
    """
    method = path = host = ua = ""
    try:
        text = data.decode("latin-1", errors="replace")
        lines = text.split("\r\n")
        if lines:
            req_line = lines[0].split(" ", 2)
            if len(req_line) >= 2:
                method, path = req_line[0], req_line[1]
        for line in lines[1:]:
            if not line:
                break
            name, _, value = line.partition(":")
            name = name.strip().lower()
            value = value.strip()
            if name == "host":
                host = value
            elif name == "user-agent":
                ua = value
    except Exception:  # pragma: no cover — pure best-effort
        pass
    return method, path, host, ua


class HTTPCloser:
    def __init__(self, body: bytes, log_path: Path) -> None:
        self.body = body
        self.log_path = log_path
        self._response = self._build_response(body)

    @staticmethod
    def _build_response(body: bytes) -> bytes:
        headers = (
            "HTTP/1.1 200 OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "Server: honeycow\r\n"
            "\r\n"
        ).encode("ascii")
        return headers + body

    async def handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        src_ip = peer[0] if peer else "?"
        src_port = peer[1] if len(peer) >= 2 else 0
        sockname = writer.get_extra_info("sockname")
        dst_bind = f"{sockname[0]}:{sockname[1]}" if sockname else ""
        start = time.monotonic()

        request_data = b""
        try:
            try:
                request_data = await asyncio.wait_for(
                    reader.read(_HTTP_READ_MAX),
                    timeout=_HTTP_READ_TIMEOUT,
                )
            except (TimeoutError, OSError):
                pass

            try:
                writer.write(self._response)
                await writer.drain()
            except OSError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        method, path, host, ua = _parse_request(request_data)
        honey_logging.write_jsonl(self.log_path, {
            "schema_version": honey_logging.SCHEMA_VERSION,
            "ts": honey_logging.now_iso(),
            "event": "http_closer",
            "transport": "http",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_bind": dst_bind,
            "method": method,
            "path": path,
            "host": host,
            "user_agent": ua,
            "request_bytes": len(request_data),
            "response_bytes": len(self._response),
            "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
        })


async def serve(
    bind_v4: str,
    bind_v6: str,
    port: int,
    body: bytes,
    log_path: Path,
) -> list[asyncio.AbstractServer]:
    """Bind HTTP servers and return them. The caller drives serve_forever."""
    closer = HTTPCloser(body, log_path)
    servers: list[asyncio.AbstractServer] = []

    v4 = await asyncio.start_server(closer.handle, bind_v4, port, backlog=50)
    servers.append(v4)
    log.info("HTTP listening on %s:%d", bind_v4, port)

    if bind_v6:
        try:
            v6 = await asyncio.start_server(
                closer.handle, bind_v6, port, backlog=50,
            )
            servers.append(v6)
            log.info("HTTP listening on [%s]:%d", bind_v6, port)
        except OSError as exc:
            log.warning("IPv6 HTTP bind failed: %s", exc)

    return servers
