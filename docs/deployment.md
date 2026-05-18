# Deployment

HoneyCow is intended to run as a Docker Compose service on a small,
abuse-tolerant VPS with public UDP and TCP port 53 and TCP port 80
available. Local development uses high ports so root is not required.

## Local Development

```bash
make venv
HONEY_PUBLIC_A=127.0.0.1 make run

dig @127.0.0.1 -p 15353 A target.example.com
dig @127.0.0.1 -p 15353 SOA arbitrary.tld
dig @127.0.0.1 -p 15353 +short TXT random.thing
curl -H 'Host: anything.com' http://127.0.0.1:18080/
```

`make run` sets `HONEY_PORT` to `DEV_DNS_PORT` (default 15353),
`HONEY_HTTP_PORT` to `DEV_HTTP_PORT` (default 18080), and writes logs
to `DEV_LOG` (default `/tmp/honeycow.jsonl`).

## Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `HONEY_PUBLIC_A` | Yes | (none) | Public IPv4 of the VPS. NS glue + default sinkhole. |
| `HONEY_PUBLIC_AAAA` | No | empty | Public IPv6. Empty disables v6. |
| `HONEY_SINKHOLE_A` | No | `HONEY_PUBLIC_A` | Override for synthesized A target. |
| `HONEY_SINKHOLE_AAAA` | No | `HONEY_PUBLIC_AAAA` | Override for synthesized AAAA target. |
| `HONEY_DOMAIN` | No | `honeycow.net.` | Identity domain. |
| `HONEY_NS_HOSTS` | No | `ns1.honeycow.net,ns2.honeycow.net` | Comma-separated NS hostnames. |
| `HONEY_ABUSE_EMAIL` | No | `abuse@honeycow.net` | SOA RNAME source. |
| `HONEY_ABUSE_URL` | No | `https://honeycow.net` | Reference URL (used in HTTP page). |
| `HONEY_TXT_CALLING_CARD` | No | the standard line | TXT payload for every TXT query. |
| `HONEY_PORT` | No | `53` | DNS UDP+TCP listen port. |
| `HONEY_HTTP_PORT` | No | `80` | HTTP TCP listen port; 0 disables. |
| `HONEY_BIND_V4` | No | `0.0.0.0` | IPv4 bind. |
| `HONEY_BIND_V6` | No | `::` | IPv6 bind. Empty disables v6. |
| `HONEY_LOG` | No | `/var/log/honeycow/events.jsonl` | JSONL event log path. |
| `HONEY_EXEMPTION_FILE` | No | `/etc/honeycow/exemptions.txt` | Exemption list path. |
| `HONEY_STATIC_INDEX` | No | `/app/static/index.html` | HTTP closer body source. |
| `HONEY_TCP_TIMEOUT` | No | `5.0` | TCP read timeout (seconds). |
| `HONEY_TCP_MAX_CONNS` | No | `50` | Concurrent TCP connection cap. |
| `HONEY_TCP_ACCEPT_BACKLOG` | No | `100` | TCP accept backlog. |
| `HONEY_TCP_MAX_QUERIES_PER_CONN` | No | `32` | Reused TCP messages before close. |
| `HONEY_UDP_RATELIMIT_ENABLED` | No | `1` | Enable UDP response rate limiting. |
| `HONEY_UDP_RATELIMIT_RATE` | No | `200` | Token refill rate per source/class. |
| `HONEY_UDP_RATELIMIT_BURST` | No | `400` | Token bucket burst size. |

## Docker Compose

```bash
cp .env.example .env    # edit HONEY_PUBLIC_A and friends
export $(grep -v '^#' .env | xargs)
docker compose build
docker compose up -d
docker compose logs -f -t
```

The Compose service publishes `53/udp`, `53/tcp`, and `80/tcp`, writes
events to the `honeycow_logs` named volume, bind-mounts
`exemptions.txt` from the repo, runs read-only, and keeps only the
`NET_BIND_SERVICE` capability.

After startup:

```bash
make smoke HOST=127.0.0.1
make logs
```

## Registrar Delegation

The core squatting works regardless — scanners hit the VPS directly.
But for the bluff to look complete, `honeycow.net` should resolve and
its public web page at `https://honeycow.net` should serve from
somewhere respectable (not the squatter VPS itself).

A typical setup at the registrar / parent zone:

```bind
honeycow.net.       IN  NS    ns1.deflationhollow.net.
honeycow.net.       IN  NS    ns2.deflationhollow.net.
honeycow.net.       IN  A     <docker-nyc3 public ipv4>    ; serves the website
ns1.honeycow.net.   IN  A     <honeycow vps public ipv4>    ; glue for the bluff
ns2.honeycow.net.   IN  A     <honeycow vps public ipv4>
```

The website at `honeycow.net` lives on a respectable host (operator's
main infrastructure with a real TLS cert). The honeycow VPS only runs
the squatter and the HTTP closer.

## Exemption Workflow

The exemption list is `exemptions.txt` in the repo, bind-mounted into
the container at `/etc/honeycow/exemptions.txt`. To add an entry:

```bash
echo 'example.com' >> exemptions.txt
docker exec honeycow kill -HUP 1
docker compose logs --tail=20 honey-ns | grep 'exemption list reloaded'
```

Parse failures leave the existing list in effect.

## Verification

```bash
make lint
make test
make smoke HOST=<vps-ipv4>
```

Manual probes:

```bash
HOST=<vps-ipv4>

dig @$HOST A target.example.com               # synthesized sinkhole A
dig @$HOST SOA random.tld                     # synthesized SOA
dig @$HOST TXT scanner.probe                  # calling-card TXT
dig @$HOST AXFR example.com | grep REFUSED    # zone transfer refused
dig @$HOST -t HS A example.com | grep REFUSED # non-IN class refused
curl -sI http://$HOST/                        # HTTP closer headers
```

## Operations

- Tail runtime events with `make logs` or `docker compose logs -f -t`.
- Edit `exemptions.txt` and `docker exec honeycow kill -HUP 1` to
  reload the block list without restarting.
- Use UFW on the VPS for IP-level abuse; the app does not block by IP.
- `HONEY_BIND_V6=` disables IPv6 binding if the VPS lacks it.
- Rebuild the Docker image after changing `static/index.html` (it is
  baked into the image at build time).
