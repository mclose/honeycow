"""Catch-all HTTP closer for the honeycow VPS.

Every connection — any Host header, any path — gets the same explanation
page back. Scanners who follow the DNS bluff (where every A record points
at this server's IP) hit this instead of a refused connection.

Lives in the same asyncio process as honey_ns.py. Reads the static page
at startup; if unreadable, serves a minimal hard-coded fallback.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
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

# Placeholder substituted with the client IP per-request. Lives in the
# static index.html so the cowsay footer can show the visitor their own IP.
_CLIENT_IP_PLACEHOLDER = "{client_ip}"
_COWSAY_PLACEHOLDER = "{cowsay_block}"


def _cowsay(lines: list[str]) -> str:
    """Render a tiny two-or-more-line cowsay bubble with the canonical cow.

    Not a full cowsay implementation — honeycow only ever feeds it a
    2-line message (welcome + client IP), so we render the multi-line
    bubble form (top/bottom corners are /\\ and \\/ respectively, no
    middle `|` rows since we never have 3+ lines).
    """
    if len(lines) < 2:
        lines = lines + [""] * (2 - len(lines))
    width = max(len(line) for line in lines)
    top = " " + "_" * (width + 2)
    bottom = " " + "-" * (width + 2)
    out = [top]
    out.append(f"/ {lines[0].ljust(width)} \\")
    for mid in lines[1:-1]:
        out.append(f"| {mid.ljust(width)} |")
    out.append(f"\\ {lines[-1].ljust(width)} /")
    out.append(bottom)
    out.append(r"        \   ^__^")
    out.append(r"         \  (oo)\_______")
    out.append(r"            (__)\       )\/\ ")
    out.append(r"                ||----w |")
    out.append(r"                ||     ||")
    return "\n".join(out)


def render_body(template: bytes, client_ip: str) -> bytes:
    """Substitute the cowsay block + client IP into the page template.

    `client_ip` is HTML-escaped before substitution. In production it's
    always a numeric IP literal from `socket.getpeername()` (defended
    further by the _resolve_client_ip XFF validation), but the escape
    is defense-in-depth — it keeps the page safe if a future change
    ever lets a non-numeric value reach this path or moves the
    {client_ip} placeholder out of a <pre> block.
    """
    safe_ip = html.escape(client_ip, quote=True)
    cowsay = _cowsay(["Welcome to the pasture!", safe_ip])
    rendered = template.decode("utf-8", errors="replace")
    rendered = rendered.replace(_COWSAY_PLACEHOLDER, cowsay)
    rendered = rendered.replace(_CLIENT_IP_PLACEHOLDER, safe_ip)
    return rendered.encode("utf-8")

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


def _parse_request(data: bytes) -> tuple[str, str, str, str, str]:
    """Pull method, path, Host, User-Agent, and X-Forwarded-For from a request.

    All fields are best-effort and never raise — the closer logs whatever
    it can see and serves the same body either way.

    Extracted values are sanitized: control characters are stripped and
    each field is truncated to a sane maximum. The JSONL log encodes
    quotes/newlines safely, but downstream tools (morning_report.py)
    print these strings directly to operators' terminals — bare ANSI
    escape sequences or control characters in a User-Agent could
    redraw the terminal or hide content. Stripping them at the edge
    keeps every consumer safe.
    """
    method = path = host = ua = xff = ""
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
            elif name == "x-forwarded-for":
                xff = value
    except Exception:  # pragma: no cover — pure best-effort
        pass
    return (
        _sanitize_header_value(method, max_len=16),
        _sanitize_header_value(path, max_len=512),
        _sanitize_header_value(host, max_len=256),
        _sanitize_header_value(ua, max_len=512),
        _sanitize_header_value(xff, max_len=256),
    )


def _sanitize_header_value(value: str, max_len: int) -> str:
    """Strip control characters and truncate. Tab is kept (whitespace)."""
    cleaned = "".join(c for c in value if c == "\t" or c >= " ")
    return cleaned[:max_len]


def _is_trusted_proxy(ip: str) -> bool:
    """True when the on-wire peer is a private/loopback address.

    The honeycow closer is fronted by Caddy on the docker bridge in
    production; any non-private peer means something hit the closer
    socket directly and its XFF header cannot be trusted.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _resolve_client_ip(peer_ip: str, xff: str) -> str:
    """Pick the real client IP from XFF when the peer is a trusted proxy.

    Caddy v2's reverse_proxy overwrites X-Forwarded-For with the immediate
    client's IP by default, so the chain is normally a single entry. If
    Caddy is later configured with trusted_proxies it will append instead,
    in which case the rightmost entry is the one Caddy itself recorded —
    anything to the left was supplied by the client and may be spoofed.
    Either way, taking the rightmost is correct.
    """
    if not xff or not _is_trusted_proxy(peer_ip):
        return peer_ip
    last = xff.rsplit(",", 1)[-1].strip()
    try:
        ipaddress.ip_address(last)
    except ValueError:
        return peer_ip
    return last


_BUDGET_EXHAUSTED_BODY = b"honeycow: rate ceiling reached.\n"
_BUDGET_EXHAUSTED_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Length: " + str(len(_BUDGET_EXHAUSTED_BODY)).encode() + b"\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Cache-Control: no-store\r\n"
    b"Connection: close\r\n"
    b"Server: honeycow\r\n"
    b"\r\n" + _BUDGET_EXHAUSTED_BODY
)


class HTTPCloser:
    def __init__(self, body: bytes, log_path: Path, budget=None) -> None:
        # `body` is the page template containing {cowsay_block} and
        # {client_ip} placeholders. The rendered response varies per
        # request (each visitor sees their own IP in the cowsay footer),
        # so we don't pre-build a single response anymore.
        # `budget` is an optional OutboundBudget; when exhausted, the
        # closer returns a tiny 503 instead of the full templated page.
        self.body_template = body
        self.log_path = log_path
        self.budget = budget

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
        response = b""
        try:
            try:
                request_data = await asyncio.wait_for(
                    reader.read(_HTTP_READ_MAX),
                    timeout=_HTTP_READ_TIMEOUT,
                )
            except (TimeoutError, OSError):
                pass

            # Parse request + resolve client IP BEFORE writing the
            # response — the cowsay footer needs the client IP.
            method, path, host, ua, xff = _parse_request(request_data)
            client_ip = _resolve_client_ip(src_ip, xff)
            body = render_body(self.body_template, client_ip)
            response = self._build_response(body)

            # Outbound byte budget check — if exhausted, send the tiny
            # 503 instead of the full closer page. The 503 is small
            # enough to fit within whatever budget remains (or forced
            # through if not).
            if self.budget is not None and not self.budget.try_charge(len(response)):
                response = _BUDGET_EXHAUSTED_RESPONSE
                self.budget.force_charge(len(response))

            try:
                writer.write(response)
                await writer.drain()
            except OSError:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        # Re-parse for the log line in the (unlikely) case rendering
        # raised before assignment. This keeps logging robust even on
        # exotic-encoding requests.
        if not response:
            method, path, host, ua, xff = _parse_request(request_data)
            client_ip = _resolve_client_ip(src_ip, xff)

        honey_logging.write_jsonl(self.log_path, {
            "schema_version": honey_logging.SCHEMA_VERSION,
            "ts": honey_logging.now_iso(),
            "event": "http_closer",
            "transport": "http",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_bind": dst_bind,
            "client_ip": client_ip,
            "forwarded_for": xff,
            "method": method,
            "path": path,
            "host": host,
            "user_agent": ua,
            "request_bytes": len(request_data),
            "response_bytes": len(response),
            "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
        })


async def serve(
    bind_v4: str,
    bind_v6: str,
    port: int,
    body: bytes,
    log_path: Path,
    budget=None,
) -> list[asyncio.AbstractServer]:
    """Bind HTTP servers and return them. The caller drives serve_forever."""
    closer = HTTPCloser(body, log_path, budget=budget)
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
