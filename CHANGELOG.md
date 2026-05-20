# Changelog

All notable changes to HoneyCow are noted here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Continuation of 2026-05-20's iteration after the [0.10.0] tag. Driven
mostly by polish + abuse-defensibility hardening that surfaced from
landing the public-repo flip and closing DigitalOcean ticket #12245819
("matter resolved" via Security Operations the same day).

### Added

- **Outbound byte budget circuit breaker** (`squatter/budget.py`). Hard
  cap on total response bytes over a rolling 60-min window (100 MB /
  3600s by default; env-tunable via `HONEY_OUTBOUND_BUDGET_BYTES` and
  `HONEY_OUTBOUND_BUDGET_WINDOW`). When exhausted: UDP gets TC=1 +
  empty sections, TCP gets REFUSED, HTTP gets a tiny 503. Belt-and-
  suspenders defense against amplification participation beyond the
  per-source rate limiter; ~2000× headroom over normal traffic so
  false-trip is essentially impossible.
- **`make prove-tc1 HOST=...`** target + a "Verify yourself" section
  on the closer page and a "Verify it yourself" section on the
  honeycow.net explainer page. Both expose a single `dig +ignore`
  command (with a literal moo-themed 240-char qname) that
  demonstrates AA=1 / RA=0 / TC=1 in one wire exchange. The pages'
  audience is abuse-desk reviewers and curious researchers who want
  to reproduce the technical claim independently.
- **Caddy templating on the honeycow.net explainer.** Enabled the
  `templates` directive, added a `{{.RemoteIP}}` cowsay footer
  matching the closer's, and an ISO-8601 render-time heartbeat
  comment as a freshness marker.
- **tire-kick coverage round 2** (`tests/tire_kick.sh`): three new
  probes — v4 TCP IXFR REFUSED, v4 UDP MAILA meta-qtype FORMERR, v4
  UDP HESIOD-class REFUSED. Tire-kick now exercises all six dispatch
  arms (synth_a / synth_soa / exempt / refused_xfr / refused_class /
  formerr_meta_qtype) plus the CHAOS bluff path, HTTP closer, and
  HTTPS explainer — 14 probes total.
- **Morning-report reflection-attempt section.** Surfaces query_drop
  events with `src_port=53` and `DROPPED_QR` / `oversized_datagram`
  reason as a first-class section: total response packets, distinct
  reflector IPs, largest reflected response size, top reflectors.
  Captures the "someone spoofed our IP and used some NS as a
  reflector" signal that previously sat invisible in the JSONL.

### Changed

- **Reverted PR #12's first cut on the explainer cowsay**: sprig's
  `max`/`len` return `int64`; Go-template's `printf "%-*s"` wants
  `int`. Briefly 500'd honeycow.net on first deploy. Fixed via
  explicit `int` casts on the width values.
- **Caddy mount switched from single-file to directory bind**
  (`./caddy/Caddyfile` → `./caddy/`). Same single-file inode-pinning
  bug as we hit on `config/exemptions.txt` earlier; same fix.
  CLAUDE.md gotcha updated to call out both occurrences.

### Fixed

- **Security audit MEDIUM findings** (`PR #15`):
  - `TokenBucketRateLimiter._buckets` is now LRU-capped at 65536
    entries (default). Without the cap, spoofed-source UDP floods
    could grow the dict until the container's `mem_limit` killed
    the process and triggered a restart loop. The cap is the
    application-side companion to the outbound-byte-budget cap above.
  - `render_body` now `html.escape()`s `client_ip` before
    substitution. Defense-in-depth before the closer page went
    public; today the value is always a numeric IP literal, but the
    escape future-proofs the templating against any future change
    that lets a non-numeric value reach the path.
  - `_parse_request` strips control characters from header values
    and truncates each to a sane max. The JSONL encoder already
    handles this safely, but `morning_report.py` prints header
    values directly to operator terminals — bare ANSI escapes could
    redraw the terminal or hide content.
  - tcpdump + Zeek sidecars dropped `NET_ADMIN`; `NET_RAW` alone is
    sufficient for passive `AF_PACKET` capture.

### Repository

- **`mclose/honeycow` flipped public** with MIT LICENSE, CI badge,
  branch protection (PR required, CI must pass), two-remote deploy
  (origin + prod bare repo), 21 merged PRs of debugging-arc history.
- **PTR records set** for both v4 (`142.93.181.53`) and v6
  (`2604:a880:800:14:0:2:f83c:0`) pointing at `honeycow.net`.
  FCrDNS-aligned in both directions.
- **DigitalOcean ticket #12245819 resolved** via Security Operations
  the same day (~12h round-trip from send). Technical mitigation +
  factual framing + probe-log proof was the recipe; no legal-policy
  routing.

## [0.10.0] — 2026-05-20

First substantive iteration past the initial implementation. Driven by
DigitalOcean abuse ticket #12245819 (Shadowserver-style open-resolver
classifier), which exposed a stack of latent deploy-pipeline issues and
motivated the abuse-defensibility hardening.

### Added

- **Scanner-research zone exemptions.** Names under `shadowserver.org`,
  `cybergreen.net`, `cyberresilience.io`, `internet-measurement.com`,
  `internet-census.org`, and `asertdnsresearch.{com,net}` now return
  REFUSED rather than synthesized answers, while still being logged.
  Shadowserver's next scan drops us off the open-resolver report.
- **RFC reserved-zone refusals** (RFC 6761 / 2606 / 6303 / 4193): 39 new
  entries covering `.localhost` / `.local` / `.test` / `.example` /
  `.invalid`, the `example.{com,org,net}` documentation domains, RFC 1918
  reverse zones, loopback / broadcast / link-local reverses, and IPv6 ULA
  + loopback reverses.
- **Wire-monitoring sidecars** in the prod stack: tcpdump (7-day hourly
  pcap ring buffer, BPF-filtered to :53/:80/:443), Zeek (JSON `local`
  script — conn.log, dns.log, http.log, weird.log, etc.), and a tiny
  wire-cleanup loop pruning Zeek logs older than 7 days. Independent
  ground truth in case our own JSONL parser drops or abuse-desk claims
  need verification.
- **`make tire-kick`** — end-to-end probe + log-correlation harness.
  Issues 11 probes (v4/v6 × UDP/TCP bluff, exempt, reserved, AXFR, SOA,
  CHAOS `version.bind`, HTTP closer, HTTPS explainer) with per-run
  nonce qnames; asserts each probe shows up in `events.jsonl` with the
  expected `handler` / `rcode` / `src_ip` family. HTTP body assertions
  cover the closer's "observably not an open resolver" content + cowsay
  rendering. HTTPS explainer probe asserts Caddy templates ran and the
  heartbeat timestamp is within 60s.
- **`make logs-wire`** + **`make report-wire`** — inspect pcaps + tail
  current Zeek `dns.log`; cross-check Zeek's DNS query count against
  honeycow's `events.jsonl` over a window to surface parser/rate-limit
  drops.
- **GitHub private repo** + **CI workflow** (`.github/workflows/ci.yml`
  — ruff + pytest on push/PR) + **branch protection** (`main` requires
  PR + passing CI to merge, no force push, no delete).
- **Two-remote deploy pipeline**: `origin` (GitHub) + `prod` (bare repo
  on the VPS at `~/honeycow.git` with a post-receive hook that checks
  out `main` and runs `make up-prod`). `make deploy` pushes both
  remotes; the prod push triggers the redeploy.
- **HTTP closer per-request templating.** `static/index.html` is now a
  template; `honey_http.py` resolves the visitor's IP (via XFF +
  trusted-proxy logic) and substitutes `{client_ip}` / `{cowsay_block}`
  placeholders. New closer body is the abuse-desk answer-key — explicit
  enumeration of wire-level differences (AA=1 / RA=0 / no EDNS / 512B +
  TC=1 / per-source rate limiting / AXFR-IXFR REFUSED / reserved-zone
  REFUSED / scanner-research REFUSED) with a centered cowsay footer
  greeting the visitor's IP.
- **Caddy templates on the explainer site.** `static/honeycow_net.html`
  is now templated by Caddy at request time; matching cowsay footer +
  ISO-8601 render-time heartbeat for cache/freshness verification.
- **Morning report "research scanners (REFUSED, still observed)"
  section** — buckets the new exempt traffic by org with src_ips,
  qnames, and refused counts.

### Changed

- **Conformed Makefile and compose to `~/projects/project-guides`
  standards** (META-CLAUDE.md Appendix A). Dropped the `docker-` prefix
  from `build` / `up` / `down` / `logs`, replaced the hand-written help
  block with the awk-parsed `## description` pattern, added
  `.DEFAULT_GOAL := help` so bare `make` never accidentally deploys,
  and filled in the canonical missing targets (`fmt`, `check`, `hooks`,
  `restart`, `rebuild`, `status`, `shell`, `deploy`, `setup-remote`,
  `_sandbox_check`). The in-container JSONL tail moved to
  `events-tail` so `logs` could mean compose-logs per house convention.
- **Merged the Caddy compose overlay into the prod overlay.** Caddy +
  acme.sh are mandatory production architecture (honeycow.net needs
  HTTPS, honeycow itself can't terminate TLS), not opt-in. One
  canonical command: `make up-prod`. `docker-compose.caddy.yml` removed.
- **`make up-prod` now `--build`s.** Without this, Python and static-file
  changes were silently checked out into the working tree but never
  reached the running container image. (Latent bug since project start.)
- **`make up-prod` reloads Caddy after compose up** so Caddyfile edits
  take effect without manual restart.
- **Bind mounts switched to directory binds.** Single-file bind mounts
  (`./exemptions.txt`, `./caddy/Caddyfile`) inode-pin to the source at
  container-start time; atomic-rename writes (rsync, editors, deploy
  hook) silently miss the container. Moved exemptions to
  `config/exemptions.txt`, mount `./config/` and `./caddy/` as
  directories.
- **Restructured `CLAUDE.md` to the house pattern.** Hoisted hard rules,
  added a Gotchas section capturing the bind-mount / kill-binary /
  caddy-mandatory traps, added a Deploy topology section now that the
  two-remote pattern is real.
- **Rewrote `static/honeycow_net.html`** (the explainer Caddy serves at
  `https://honeycow.net/`) to mirror the closer's abuse-defensibility
  content while preserving its welcoming tone.

### Fixed

- **IPv6 source-IP rewriting.** With v4-only docker network, docker-proxy
  translated v6 ingress to the bridge gateway IP — honeycow logged every
  v6 query as `src_ip: 172.18.0.1`. Enabling `enable_ipv6: true` with a
  ULA subnet on the prod network gives the container a v6 address; the
  real client IP is preserved through to the container and the JSONL.
- **Env-var name mismatch** between `docker-compose.prod.yml`
  (`HONEY_PUBLIC_IPV4`/`IPV6`) and `.env` (`HONEY_PUBLIC_A`/`AAAA`).
  Reconciled to the latter.
- **Cowsay-template int-cast bug** (sprig's `max`/`len` return `int64`;
  Go-template `printf "%-*s"` wants `int`). Briefly 500'd
  honeycow.net on first deploy.
- **Zeek's checksum-offload packet drops.** Added `-C` to ignore the
  hardware-offloaded TCP/UDP checksum that cloud NICs surface as 0.

### Removed

- `docker-compose.caddy.yml` — folded into `docker-compose.prod.yml`.
- `exemptions.txt` (root) — moved to `config/exemptions.txt`.

## [0.1.1] — 2026-05-19

Pre-production hardening pass: Caddy + acme.sh overlay, identity
parameterization, optional HTTP bind, themed CHAOS handling, real client
IP through Caddy, host-rebuild runbook, and the daily morning report.

### Added

- Caddy + acme.sh sidecar overlay for HTTPS on honeycow.net (DNS-01 via
  BIND nsupdate / RFC 2136) and reverse-proxy of port 80 to the honey-ns
  closer.
- Themed `version.bind` bluff via `HONEY_VERSION_BIND_TXT`.
- CHAOS-class queries handled with the bluff (TXT returns calling-card,
  ANY returns RFC 8482 HINFO, other CH qtypes NOERROR/empty) instead of
  the previous blanket REFUSED.
- HTTP closer logs `client_ip` (resolved via `X-Forwarded-For` when the
  on-wire peer is private/loopback) and `forwarded_for` (raw header).
- `docs/bootstrap.md` — from-scratch host-rebuild runbook covering every
  non-vanilla touch (systemd-resolved, Docker, UFW + ufw-docker, TSIG,
  first-time cert issue).
- `tools/morning_report.py` + `make report` — daily summary of
  events.jsonl ± `ufw.log`: v4/v6 split, scanner-fingerprint families,
  top probed ports, IPs overlapping UFW + HoneyCow, optional CT-log
  spike check.
- `HONEY_BIND_V6=""` disables IPv6 binding for hosts without it.

### Changed

- Identity defaults parameterized; repo-specific GitHub URLs dropped
  from the served pages.

## [0.1.0] — 2026-05-18

Initial implementation, forked from chaoscow's listener / logging
skeleton.

### Added

- asyncio UDP + TCP DNS server with synthesized authority-claiming
  responses for any queried name.
- Squatter dispatch with full-bluff QTYPE switch: A, AAAA, NS, SOA, MX,
  TXT, ANY (minimal RFC 8482 HINFO), NODATA fallback for other types.
- Exemption list — text file, SIGHUP reload, parse-fail safety (keeps
  previous list on bad file).
- HTTP catch-all closer on port 80 serving a fixed explanation page.
- JSONL event log shared by DNS and HTTP listeners.
- Env-driven identity strings (`HONEY_DOMAIN`, `HONEY_NS_HOSTS`,
  `HONEY_ABUSE_EMAIL`, `HONEY_TXT_CALLING_CARD`,
  `HONEY_SINKHOLE_A`/`AAAA`); committed defaults are placeholders.
- Docker Compose project with non-root container, read-only filesystem,
  DNS-native healthcheck, bind-mounted exemption file.
- pytest unit suite covering dispatch, synthesis, exemption loader, env
  parsing, and deployment file shape.

[Unreleased]: https://github.com/mclose/honeycow/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/mclose/honeycow/compare/v0.1.1...v0.10.0
[0.1.1]: https://github.com/mclose/honeycow/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mclose/honeycow/releases/tag/v0.1.0
