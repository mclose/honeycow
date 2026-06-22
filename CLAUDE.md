# HoneyCow Agent Context

## What this project is

HoneyCow is a Python NS-squatting DNS honeypot. It synthesizes
authoritative-looking responses (A, AAAA, NS, SOA, MX, TXT) for every
queried name in every zone, pointing A/AAAA at a configurable sinkhole
IP that defaults to the honeycow VPS itself. A catch-all HTTP closer on
port 80 returns an explanation page to scanners who follow the bluff.

Sibling of [chaoscow](https://github.com/mclose/chaoscow) with the
opposite design contract: chaoscow is RFC-polite authoritative for one
zone (REFUSED for everything else); honeycow is gleefully
authoritative-claiming for every zone (REFUSED only for names on the
exemption list).

## Where docs live

- `CLAUDE.md` — this file (rules + context for Claude)
- `README.md` — human onboarding
- `docs/architecture.md` — wire behavior and dispatch table
- `docs/bootstrap.md` — host rebuild runbook
- `docs/deployment.md` — operational detail
- `docs/rationale.md` — design rationale
- `docs/herd.md` — multi-VPS herd architecture (spec; not yet built)

## Deploy topology

Two-remote:

- `origin` → `git@github.com:mclose/honeycow.git` (private; CI on push/PR)
- `prod` → `honeycow:honeycow.git` (bare repo, post-receive hook
  checks out main into `~/projects/honeycow` and runs `make up-prod`)

Branch protection on `main` is fully enforced (`enforce_admins: true`):
**nobody can push directly to `main`, admins included** — no silent
bypass. The only override is the sole admin (Matthew) deliberately
toggling the rule in repo settings; never force/bypass on his behalf.

So `make deploy` no longer pushes to origin. The workflow is: branch →
PR → passing CI (`check`/ruff) → merge on GitHub → `make deploy`, which
fetches the merged `origin/main`, fast-forwards local `main`
(`--ff-only`), and pushes to `prod` (not gated; post-receive runs
`make up-prod`).

The prod stack is honey-ns + caddy (TLS for honeycow.net, reverse-proxy
to honey-ns:80 for anything else) + acme (issues/renews honeycow.net
cert via DNS-01 over BIND nsupdate). All three are required.

## Hard rules

- **Never hardcode identity strings.** `honeycow.net`, abuse address,
  VPS IP — env-driven only. Reason: production values live in
  gitignored `.env`; committed defaults are placeholders. Tests use
  defaults from `tests/conftest.py`.
- **Don't bleed honeycow patterns into chaoscow.** Opposite design
  contracts. Honeycow = gleeful authoritative-claim for every zone;
  chaoscow = RFC-polite for one zone. Keep them separate.
- **Never `docker compose down -v`.** Would destroy the `honeycow_logs`
  volume and lose all event history.
- **Never edit `config/exemptions.txt` via atomic-rename writes only on
  the VPS.** Editors and rsync are fine because the bind mount is on
  the parent directory (see Gotchas) — but if you ever switch back to a
  single-file bind mount, those writes won't propagate.

## Gotchas

- **No `kill` binary in the container.** The image is minimal +
  read-only. To reload exemptions, use `docker kill -s HUP honeycow`
  from the host. `docker exec honeycow kill -HUP 1` fails with "executable
  file not found in $PATH".
- **Bind-mount inode pinning.** We bind-mount the `config/` and `caddy/`
  directories (not the single `config/exemptions.txt` / `caddy/Caddyfile`
  files) for a reason: single-file bind mounts pin to the source inode at
  container-start time, so atomic-rename writes (rsync, vim, most editors,
  our own Edit tool) replace the file at the same path but a different
  inode — and the container keeps reading the original inode's contents.
  Directory binds re-resolve filenames on every access; any write strategy
  works. We hit this twice: first on `exemptions.txt`, then on `Caddyfile`
  when enabling templating — the `templates` directive landed in the host
  file but the container kept serving the pre-templating Caddyfile until
  it was restarted.
- **Caddy + acme are mandatory, not opt-in.** honeycow.net needs HTTPS
  (Caddy terminates TLS) and honeycow itself can't (and shouldn't) terminate
  TLS. The merged `docker-compose.prod.yml` reflects this. There is no
  separate `docker-compose.caddy.yml` anymore.
- **No EDNS / no recursion advertised.** AA=1, RA=0 on every synthesized
  response. EDNS OPT records are intentionally omitted. Responses cap
  at 512 bytes with TC=1 to force TCP fallback rather than EDNS-style
  amplification.
- **Outbound byte budget circuit breaker.** `OutboundBudget` (in
  `squatter/budget.py`) caps total response bytes at 100 MB per rolling
  60-min window (configurable via `HONEY_OUTBOUND_BUDGET_BYTES` /
  `HONEY_OUTBOUND_BUDGET_WINDOW`). Belt-and-suspenders defense against
  amplification participation: ~2000x normal traffic headroom, but if
  ever exhausted, UDP responses become TC=1 + empty, TCP REFUSED,
  HTTP 503. State is in-memory only; container restart resets the
  budget. Charge applies to *what we actually emit* (including
  substitutes), so a budget-exhausted burst can't be bypassed by
  retrying.
- **DigitalOcean / Shadowserver "open resolver" pipeline.** Shadowserver
  scans the v4 internet with `A dnsscan.shadowserver.org` and reports
  answerers to hosting providers. We REFUSE for known scanner-research
  zones (see `config/exemptions.txt`'s scanner-research block) to stay off
  the report, while still logging the probes. Don't remove those exemptions.
  Complementary defense: `config/source_exemptions.txt` REFUSEs by source
  CIDR, catching scanners that fingerprint via off-zone names — the qname
  list alone misses `TXT google.com` / `TXT version.bind` probes from
  known scanner ranges.
## Architecture (file map)

- `honey_ns.py` — asyncio UDP + TCP DNS listeners, wire parsing,
  logging, TCP connection limits, UDP rate limiting, SIGHUP handler.
- `honey_http.py` — asyncio HTTP listener serving the catch-all closer.
- `honey_logging.py` — JSONL event shaping/writing, shared by both
  listeners.
- `squatter/base.py` — identity constants, record synthesizers,
  response helpers, serialization. AA=1 / RA=0 lives here.
- `squatter/dispatch.py` — full-bluff dispatch: exemption → class →
  AXFR/IXFR → meta-qtype → QTYPE-driven synthesis.
- `squatter/exemptions.py` — qname-based REFUSED loader with SIGHUP
  reload. Parse failures keep the previous list in effect.
- `squatter/source_exemptions.py` — source-IP / CIDR REFUSED loader.
  Layer 1 defense: REFUSE by source IP regardless of qname/qtype/qclass
  (catches scanners that fingerprint via off-zone names like
  `TXT google.com.` — qname exemption can't see those). Same fail-open
  semantics + SIGHUP reload as the qname list. Handler name in events:
  `exempt_source`.
- `config/exemptions.txt` — qname REFUSED list. Bind-mounted into the
  container at `/etc/honeycow/`.
- `config/source_exemptions.txt` — source-IP REFUSED list (CIDRs from
  Shadowserver, Censys, Driftnet, ASERT). Same bind mount.
- `static/index.html` — the HTTP closer page.
- `caddy/Caddyfile` — TLS + reverse-proxy config (prod stack only).
- `tools/healthcheck.py` — container healthcheck (SOA query against self).
- `tools/morning_report.py` — daily traffic summary; see [[morning-report]]
  feedback in agent memory.

## Protocol Constraints

- UDP responses cap at 512 bytes. Oversized responses set `TC=1` with
  empty answer/authority/additional sections so clients retry over TCP.
- EDNS is intentionally unsupported. Responses omit OPT records.
- TCP uses the RFC 1035 two-byte length prefix and serves multiple
  messages per connection up to `HONEY_TCP_MAX_QUERIES_PER_CONN`.
- Every queried name gets a synthesized authoritative-looking answer
  unless it's on the exemption list (or a subname of one), in which
  case the response is `REFUSED`.
- CHAOS-class queries get the bluff: `TXT` returns the calling-card
  text in CH class, `ANY` returns the RFC 8482 HINFO in CH class, other
  CH qtypes return NOERROR / empty. Other non-IN classes (HESIOD, NONE,
  etc.) return `REFUSED`.
- AXFR / IXFR return `REFUSED` regardless of class.
- Meta qtypes (OPT, TKEY, TSIG, MAILA, MAILB) return `FORMERR`.
- `ANY` queries return one synthesized HINFO RRset (RFC 8482). Even
  honeycow stays polite on ANY-minimization; amplification would be
  obnoxious.
- The HTTP closer answers any Host header with the same static page,
  `Connection: close` after every response.

## Project-specific overrides

- venv path is `./venv` (matches the global default; explicit because
  the Makefile references `venv/bin/*` paths directly).
- Identity strings come from `.env` (gitignored); see `.env.example`
  for what to set.
