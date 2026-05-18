# HoneyCow

> honeycow: this is not the cow you are looking for. a polite ns squatter.

HoneyCow is a deliberately incorrect Python authoritative DNS server. It
synthesizes plausible-looking responses (A, AAAA, NS, SOA, MX, TXT) for
every queried name in every zone, pointing A/AAAA at a configurable
sinkhole IP that defaults to the honeycow VPS itself. A catch-all HTTP
closer on port 80 returns an explanation page to anyone who follows the
DNS bluff back to that IP.

It is the sibling of [chaoscow](https://github.com/mclose/chaoscow),
the polite cousin that serves fortunes for a single authoritative
zone. HoneyCow has the opposite design contract: chaoscow is
RFC-polite authoritative for one zone (REFUSED for everything else);
honeycow is gleefully authoritative-claiming for every zone (REFUSED
only for names on the exemption list).

## Why

Public-facing DNS sees a lot of opportunistic scanning — probes for
open recursors, zone-transfer attempts, fingerprinting queries. Real
authoritative servers respond with `REFUSED` and move on. HoneyCow
goes the other direction: it answers everything, with synthesized
authority claims that point scanners back at itself, where an HTTP
closer explains what just happened and how to ask for exemption.

The exemption list is a simple text file. Anyone whose zone gets
caught in the bluff can email `abuse@honeycow.net` and be added to a
hot-reloaded block list (SIGHUP).

## Quickstart

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt

HONEY_PUBLIC_A=127.0.0.1 make run
dig @127.0.0.1 -p 15353 A target.example.com
dig @127.0.0.1 -p 15353 SOA arbitrary.tld
dig @127.0.0.1 -p 15353 +short TXT random.thing
curl -s http://127.0.0.1:18080/
```

For Docker:

```bash
cp .env.example .env    # edit HONEY_PUBLIC_A and friends
export $(grep -v '^#' .env | xargs)
docker compose up -d
make smoke HOST=127.0.0.1
```

## Common Commands

| Command | Purpose |
| --- | --- |
| `make venv` | Create `venv/` and install development tools. |
| `make run` | Run locally on `DEV_DNS_PORT` 15353 by default. |
| `make test` | Run unit tests. |
| `make lint` | Run Ruff checks. |
| `make smoke HOST=...` | Probe a live deployment on port 53. |
| `make docker-build` | Build the Docker image. |
| `make docker-up` | Start the Docker Compose service. |
| `make logs` | Tail the JSONL event log in the container. |

## What It Serves

| Query | Response |
| --- | --- |
| Any name on the exemption list (or any subname) | `REFUSED`. |
| `<name>` A | Synthesized A pointing at `HONEY_SINKHOLE_A`. |
| `<name>` AAAA | Synthesized AAAA when `HONEY_SINKHOLE_AAAA` is set, else `NODATA`. |
| `<name>` NS | Synthesized NS RRset listing every `HONEY_NS_HOSTS` entry, plus glue. |
| `<name>` SOA | Synthesized SOA at qname (treats every name as its own zone apex). |
| `<name>` MX | Synthesized MX -> `ns1.<HONEY_DOMAIN>` plus A/AAAA glue. |
| `<name>` TXT | The `HONEY_TXT_CALLING_CARD` string. |
| `<name>` ANY | Minimal RFC 8482 HINFO. |
| `<name>` other qtype | `NODATA` with synthesized SOA in authority. |
| Non-IN class | `REFUSED`. |
| AXFR / IXFR | `REFUSED`. |
| Meta qtype (OPT/TKEY/TSIG/etc.) | `FORMERR`. |
| Any HTTP request on port 80 | Static explanation page. |

## Configuration

See `.env.example` for the full env shape. Every identity string
(domain, NS hostnames, abuse email, calling-card TXT) is env-driven
so committed source contains only placeholders.

## Documentation

- [Architecture](docs/architecture.md): request flow, modules, DNS behavior.
- [Deployment](docs/deployment.md): local setup, Docker Compose, delegation,
  smoke checks, and exemption workflow.
- [Rationale](docs/rationale.md): why this exists and what it is and isn't.
- [Agent context](CLAUDE.md): guidance for future LLM/code-agent sessions.
