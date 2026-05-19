# Changelog

All notable changes to HoneyCow are noted here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project does
not yet have releases.

## Unreleased

### Added
- Initial implementation forked from chaoscow's listener / logging skeleton:
  asyncio UDP + TCP DNS server, synthesized authority-claiming responses
  for any queried name.
- Squatter dispatch with full-bluff QTYPE switch: A, AAAA, NS, SOA, MX, TXT,
  ANY (minimal RFC 8482 HINFO), NODATA fallback for other types.
- Exemption list: simple text file, SIGHUP reload, parse-fail safety
  (existing list kept on bad file).
- HTTP catch-all closer on port 80 serving a fixed explanation page to
  scanners who follow the DNS bluff.
- JSONL event log shared by DNS and HTTP listeners.
- Identity strings env-driven (HONEY_DOMAIN, HONEY_NS_HOSTS,
  HONEY_ABUSE_EMAIL, HONEY_TXT_CALLING_CARD, HONEY_SINKHOLE_A/AAAA);
  committed defaults are placeholders.
- Docker Compose project with non-root container, read-only filesystem,
  DNS-native healthcheck, bind-mounted exemption file.
- pytest unit suite covering dispatch, synthesis, exemption loader, env
  parsing, and deployment file shape.
- HTTP closer logs `client_ip` (resolved via `X-Forwarded-For` when the
  on-wire peer is private/loopback) and `forwarded_for` (raw header) so
  Caddy-fronted deployments retain real scanner IPs in events.
- `docs/bootstrap.md` — full from-scratch host-rebuild runbook covering
  every non-vanilla touch (systemd-resolved, Docker install, UFW +
  ufw-docker, TSIG / first-time cert issue).
