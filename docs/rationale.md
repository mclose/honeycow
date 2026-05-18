# Rationale

HoneyCow exists because public-facing DNS attracts unwanted scanning,
and `REFUSED` is a missed opportunity. A polite squatter can take that
traffic, point it at itself, and use the followup connections to
explain what just happened.

## Why Build It

- Real authoritative servers see scanner traffic constantly. HoneyCow
  catches it and gives it a coherent place to land.
- The synthesized responses are predictable and well-structured, which
  makes follow-on observation (in DNS logs and HTTP logs on the same
  host) self-consistent.
- The exemption list and abuse contact make the project operable in
  good faith: any zone caught in the bluff can ask to be left alone.
- It is the natural foil to
  [chaoscow](https://github.com/mclose/chaoscow), which serves one
  zone correctly. HoneyCow serves every zone incorrectly. Together
  they cover the whole DNS contract space.

## Why Not Use a Generic Sinkhole

Sinkhole tools exist (Conpot, dnschef, etc.). HoneyCow chooses a
specific point in the design space:

- Always-on synthesis instead of pattern-matched response sets.
- One self-contained Python service with its own logging, no extra
  daemons.
- Identity baked from env so the same binary can host different
  squatters under different domains.
- HTTP closer in the same process, so DNS bluff and HTTP closer share
  the same event log.

## Why The Name

Cow is the family. ChaosCow is the polite cousin. HoneyCow is the one
that wanders into your pasture and starts answering everyone's
questions about it.

## Non-Negotiables

- Standard DNS on UDP/TCP port 53; plain HTTP on TCP 80.
- No recursion, forwarding, cache, DNSSEC, EDNS, TSIG, NOTIFY service,
  dynamic updates, AXFR, IXFR.
- Identity strings are env-driven; no real abuse address or VPS IP in
  committed source.
- Exemption requests are honored without argument. The point is the
  prank, not the harm.
- ANY queries get minimal HINFO; we do not amplify.
- IP-level abuse is the operator's job (UFW on the VPS), not the app's.
