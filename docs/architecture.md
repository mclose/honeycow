# Architecture

HoneyCow is a single-process service that runs three asyncio listeners:
DNS UDP, DNS TCP, and HTTP TCP. The DNS side parses wire messages
defensively, dispatches to a synthesis layer, and writes structured
JSONL logs. The HTTP side answers any request with a fixed page.

## Request Flow

```text
client or recursive resolver
  -> DNS UDP/TCP query on port 53
  -> honey_ns.py parses and validates the wire message
  -> squatter.dispatch checks exemption, class, qtype
  -> squatter.base synthesizes records for the queried name
  -> honey_ns.py serializes and logs the result

scanner or browser
  -> TCP connect on port 80
  -> honey_http.py reads a request prefix, logs source IP / Host / UA
  -> writes the static explanation page back, Connection: close
```

## Runtime Modules

| Module | Responsibility |
| --- | --- |
| `honey_ns.py` | Asyncio UDP/TCP DNS listeners, wire parsing, TCP framing, UDP truncation entrypoint, rate limiting, event logging, signal handling. |
| `honey_http.py` | Asyncio HTTP listener serving the catch-all closer page. |
| `honey_logging.py` | JSONL event schema and writer. |
| `squatter/base.py` | Identity constants, record synthesizers, response helpers, serialization limits. |
| `squatter/dispatch.py` | Always-answer dispatch — exemption check, class check, AXFR/IXFR refusal, meta-qtype FORMERR, QTYPE switch. |
| `squatter/exemptions.py` | Text-file loader, subdomain matching, SIGHUP reload. |
| `tools/healthcheck.py` | Container DNS healthcheck (SOA against self). |
| `static/index.html` | The HTTP closer page. |

## DNS Behavior

Honeycow has no fixed zone. Every queried name is treated as its own
zone apex when SOA / NS are requested, and arbitrary records are
synthesized for any qtype.

| Query | Response |
| --- | --- |
| Exempt name (or any subname) | `REFUSED`. |
| `<name>` A | Synthesized A -> `HONEY_SINKHOLE_A`. |
| `<name>` AAAA | Synthesized AAAA -> `HONEY_SINKHOLE_AAAA` (or `NODATA` when no v6 configured). |
| `<name>` NS | NS RRset listing every `HONEY_NS_HOSTS` entry; A/AAAA glue in additional. |
| `<name>` SOA | Synthesized SOA at qname (mname is `NS_HOSTS[0]`, rname from `HONEY_ABUSE_EMAIL`). |
| `<name>` MX | MX 10 -> `NS_HOSTS[0]`; A/AAAA glue in additional. |
| `<name>` TXT | One TXT RRset whose payload is `HONEY_TXT_CALLING_CARD`. |
| `<name>` ANY | Minimal RFC 8482 HINFO RRset only. |
| `<name>` CNAME/PTR/SRV/etc. | `NODATA` with synthesized SOA in authority. |
| `<name>` TXT (CH class) | Calling-card TXT RRset in CH class. Catches `version.bind` / `hostname.bind` / `id.server` / `authors.bind` scanner fingerprints. |
| `<name>` ANY (CH class) | Minimal RFC 8482 HINFO RRset in CH class. |
| `<name>` other (CH class) | `NOERROR` / empty answer. No IN-class auth/glue mixed in. |
| Other non-IN class (HESIOD, NONE, etc.) | `REFUSED`. |
| AXFR / IXFR | `REFUSED` (regardless of class). |
| Meta qtype (OPT/TKEY/TSIG/MAILA/MAILB) | `FORMERR`. |

The authority section of A/AAAA/SOA/TXT responses carries a synthesized
NS RRset for the queried name; the additional section carries A (and
AAAA, if configured) glue for every `HONEY_NS_HOSTS` entry.

## Transport

UDP is one datagram in, one datagram out. Responses cap at 512 bytes;
oversized responses get `TC=1` with empty sections so clients retry
over TCP. EDNS is not supported.

TCP uses the DNS two-byte length prefix. A connection serves up to
`HONEY_TCP_MAX_QUERIES_PER_CONN` queries (default 32 — higher than
chaoscow's 5 because squatter responses are often near the UDP cap
and TCP retry is the common path).

HTTP reads up to 8 KiB of request prefix with a 5-second timeout,
logs what it parsed (method, path, Host, User-Agent), and writes the
same static body. `Connection: close` after every response.

## Security Model

- No recursion, forwarding, cache, DNSSEC, EDNS, TSIG, NOTIFY service,
  dynamic updates, AXFR, IXFR.
- Every DNS message is parsed inside a `dns.exception.DNSException`
  guard.
- Packets with `QR=1` are silently dropped to avoid reflection-amplifier
  behavior.
- ANY queries return one synthesized HINFO only — the squatter has no
  business emitting large RRsets in response to a single-question ANY.
- Source IPs are logged for audit but not trusted for access control.
  IP-level blocking is the operator's job (UFW on the VPS).
- UDP rate limiting is keyed by source IP and response class.
- Docker runs with a read-only filesystem, no-new-privileges, dropped
  capabilities except `NET_BIND_SERVICE`, and bounded process/memory
  limits.

## Logging

Every DNS query, drop, and HTTP closer connection writes one JSON
object to `HONEY_LOG`, defaulting to `/var/log/honeycow/events.jsonl`
in the container. DNS records include source address, transport,
parsed question, response kind, handler, byte counts, elapsed time,
truncation, and drop reason. HTTP records include source address,
parsed Host / path / User-Agent, request and response byte counts.

## Exemption Loading

`squatter/exemptions.py` reads the configured file at startup and on
SIGHUP. Parse failures leave the existing list in effect and log a
warning — a broken exemption file does not take honeycow offline.

The match is `qname == exempt OR qname.is_subdomain(exempt)`, so a
single line `example.com` covers every name under it.
