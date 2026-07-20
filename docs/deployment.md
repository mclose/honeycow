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
events to the `honeycow_logs` named volume, bind-mounts the `config/`
directory from the repo into `/etc/honeycow/`, runs read-only, and
keeps only the `NET_BIND_SERVICE` capability.

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

The exemption list is `config/exemptions.txt` in the repo. The whole
`config/` directory is bind-mounted into the container at
`/etc/honeycow/`, so atomic-rename writes (from rsync, editors, etc.)
remain visible without a container restart. To add an entry:

```bash
echo 'example.com' >> config/exemptions.txt
docker kill -s HUP honeycow
docker compose logs --tail=20 honey-ns | grep 'exemption list reloaded'
```

`docker kill -s HUP` is used rather than `docker exec honeycow kill`
because the read-only minimal container does not ship a `kill` binary.

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
- Edit `config/exemptions.txt` and `docker kill -s HUP honeycow` to
  reload the block list without restarting.
- Use UFW on the VPS for IP-level abuse; the app does not block by IP.
- `HONEY_BIND_V6=` disables IPv6 binding if the VPS lacks it.
- Rebuild the Docker image after changing `static/index.html` (it is
  baked into the image at build time).

## Analysis Pipeline

The honeypot's raw logs live on the honeycow VPS; analysis runs on the
report host (claude), which pulls them down. The flow is three steps:

```bash
make pull       # incremental: only new bytes cross the wire
make ingest     # (re)build the local SQLite index from the raw files
make report     # fast report from the index (indexed time-window query)
make dashboard  # render the daily-watch page Caddy serves
```

`make refresh` runs `pull` + `ingest` + `dashboard` in one step (under a
lockfile), and is what the timer invokes.

Key properties:

- **Pull is incremental but full-fidelity.** Both logs are append-only, so
  `tools/pull-logs.sh` ships only the delta: a byte-offset tail of
  `events.jsonl` (the local file's size *is* the offset — no state file to
  corrupt) and `rsync --append-verify` for `ufw.log*`, where immutable `.gz`
  rotations are skipped and a rotation self-heals via full re-transfer. The
  result is byte-identical to a full copy — ~140 KB per run instead of
  237 MB. `FULL=1` forces a complete re-pull; `DRY_RUN=1` previews.
- **Nothing is summarised.** The SQLite DB is one row per event with ~every
  scalar field indexed — a reshape of the raw, not a reduction. (The lossy
  per-hour *digest* is a separate herd artifact; see `docs/herd.md`.)
- **The index is a derived, rebuildable view.** The raw JSONL/UFW stay the
  capture-of-record. If the DB is ever wrong: `make ingest REBUILD=1`.
- **Ingest is idempotent** (per-row `rowhash`), so the DB accumulates and
  its UFW history outlives the VPS's ~5-week rotation. The data dir is
  persistent (`~/honeycow-analysis`), never `/tmp`.
- `make report-raw` reads the raw files directly if you don't want to
  ingest first; `make report` reads the index and errors with a hint if it
  is missing.

### The dashboard

`make dashboard` renders a **self-contained** HTML page (data embedded as
JSON, zero network requests) into `~/www/honeycow-dash/index.html`. On claude
that directory is already served by `caddy-claude` at
`honeycow.lab.deflationhollow.net` — so there is no copy step: the SQLite
index and the web server are on the same host.

Each day is graded green / amber / red against the median of its previous 28
**complete** days. Relative rather than absolute, because one flood would
poison a mean/σ band and hide everything after it. The rubric is a single
config block at the top of `tools/dashboard.py`; every day renders which
rules fired and with what numbers, so a misbehaving threshold is visible
rather than opaque.

Two honesty rules the page keeps: UFW shows "no data retained" (never a
false `0`) for days predating rotation, and today is flagged *partial* and
excluded from the baselines so a half-day can't drag the median down.

Access is **tailnet-only** (`bind` to claude's CGNAT tailscale IP), with
UFW's default-deny as an independent second layer — a Caddyfile slip alone
cannot expose it. Adding Pocket ID later would be a Caddy `forward_auth`
concern, not an application change.

`tools/dashboard.py --dry-run` prints per-day verdicts without writing.

### Scheduled refresh (systemd user timer)

```bash
make install-timer   # copies units, enables linger, enables --now
# or manually:
cp deploy/systemd/honeycow-index.{service,timer} ~/.config/systemd/user/
loginctl enable-linger "$USER"
systemctl --user daemon-reload
systemctl --user enable --now honeycow-index.timer
systemctl --user list-timers honeycow-index.timer   # confirm next run
journalctl --user -u honeycow-index.service -n 50    # inspect a run
```

The timer fires every 4 hours anchored to `America/Chicago` (06:00, 10:00,
14:00, 18:00, 22:00 local, + jitter), so a fresh page is always waiting in
the morning. The zone is named rather than converted to UTC — systemd >= 252
resolves it, so this stays correct across DST without the hourly-tick +
`TZ=` guard that cron needs on this host. `Persistent=true` catches up a run
missed while the host was off. It runs as a *user* unit — no root.

4-hourly is affordable only because the pull is incremental (~16 s, ~140 KB
per run). That frequency is also why the page needs no "refresh" button:
a button would require a backend, whereas frequency is one line of config.
