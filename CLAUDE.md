# HoneyCow Agent Context

This file is the compact LLM-facing source of truth. For human docs,
start with `README.md`, then `docs/architecture.md` and
`docs/deployment.md`.

## Project

HoneyCow is a Python NS-squatting DNS server. It synthesizes
authoritative-looking responses (A, AAAA, NS, SOA, MX, TXT) for every
queried name in every zone, pointing A/AAAA at a configurable sinkhole
IP that defaults to the honeycow VPS itself. A catch-all HTTP closer
on port 80 returns an explanation page to scanners who follow the DNS
bluff.

It is the sibling of [chaoscow](https://github.com/mclose/chaoscow),
with the **opposite** design contract: chaoscow is RFC-polite
authoritative for one zone (REFUSED for everything else); honeycow is
gleefully authoritative-claiming for every zone (REFUSED only for
names on the exemption list).

## Current Architecture

- `honey_ns.py`: asyncio UDP and TCP DNS listeners, wire parsing,
  logging, TCP connection limits, UDP rate limiting, serialization,
  signal handling (SIGHUP reloads exemptions).
- `honey_http.py`: asyncio HTTP listener serving the catch-all closer
  page for any Host / path.
- `honey_logging.py`: JSONL event shaping and writing, shared by both
  listeners.
- `squatter/base.py`: identity constants (DOMAIN, NS_HOSTS, HOSTMASTER,
  TXT_CALLING_CARD, SINKHOLE_A/AAAA), record synthesizers, response
  helpers, serialization.
- `squatter/dispatch.py`: full-bluff dispatch — exemption check, class
  check, AXFR/IXFR refusal, meta-qtype FORMERR, then QTYPE-driven
  synthesis.
- `squatter/exemptions.py`: text-file loader with SIGHUP reload.
- `static/index.html`: the HTTP closer page.
- `tools/healthcheck.py`: container healthcheck (SOA query against self).

Active design docs:

- `docs/architecture.md`
- `docs/deployment.md`
- `docs/rationale.md`

## Commands

```bash
make venv
make lint
make test
HONEY_PUBLIC_A=127.0.0.1 make run
make smoke HOST=127.0.0.1
```

`make run` binds local DNS and HTTP sockets. In sandboxed sessions it
may require approval even on high ports.

## Runtime Requirements

- `HONEY_PUBLIC_A` is required (public IPv4 of the VPS — used as NS
  glue and as the default sinkhole target).
- `HONEY_PUBLIC_AAAA` is optional; empty disables IPv6 listeners and
  AAAA answers.
- `HONEY_SINKHOLE_A` / `HONEY_SINKHOLE_AAAA` override what synthesized
  A/AAAA answers point at; defaults to the public address.
- `HONEY_DOMAIN`, `HONEY_NS_HOSTS`, `HONEY_ABUSE_EMAIL`, and
  `HONEY_TXT_CALLING_CARD` bake the squatter identity into every
  bluffed response. The committed defaults are placeholders; production
  values live in gitignored `.env`.
- The Docker service is read-only, drops capabilities except
  `NET_BIND_SERVICE`, and writes events to the `honeycow_logs` volume.

## Protocol Constraints

- UDP responses cap at 512 bytes. Oversized responses set `TC=1` with
  empty answer/authority/additional sections so clients retry over
  TCP.
- EDNS is intentionally unsupported. Responses omit OPT records.
- TCP uses the RFC 1035 two-byte length prefix and serves multiple
  messages per connection up to `HONEY_TCP_MAX_QUERIES_PER_CONN`.
- Every queried name gets a synthesized authoritative-looking answer
  unless it is on the exemption list (or a subname of one), in which
  case the response is `REFUSED`.
- CHAOS-class queries get the bluff: `TXT` returns the calling-card text in
  CH class, `ANY` returns the RFC 8482 HINFO in CH class, other CH qtypes
  return NOERROR / empty. Other non-IN classes (HESIOD, NONE, etc.) return
  `REFUSED`.
- AXFR / IXFR return `REFUSED` regardless of class.
- Meta qtypes (OPT, TKEY, TSIG, MAILA, MAILB) return `FORMERR`.
- `ANY` queries return one synthesized HINFO RRset (RFC 8482) — even
  honeycow stays polite on ANY-minimization, since amplification would
  be obnoxious.
- The HTTP closer answers any Host header with the same static page,
  `Connection: close` after every response.

## Development Notes

- Identity strings are env-driven; never hardcode `honeycow.net`, an
  abuse address, or a VPS IP in source. Tests rely on the test-time
  defaults set in `tests/conftest.py`.
- The exemption list is hot-reloadable via `kill -HUP 1` inside the
  container; parse failures keep the previous list in effect.
- Update `docs/architecture.md` when changing wire behavior or the
  dispatch table.
- Keep `README.md` and `CLAUDE.md` short. Operational detail in
  `docs/deployment.md`; design detail in `docs/architecture.md`.
- This is the gleefully-incorrect sibling. Keep chaoscow's narrow
  RFC-polite identity separate — do not bleed honeycow patterns into
  it.
