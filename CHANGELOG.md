# Changelog

All notable changes to HoneyCow are noted here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
