# Herd Architecture

This document is the agreed design for scaling HoneyCow from a single
instance ("one cow") to a herd of low-cost drone VPSes spread across
providers and regions. It is a **specification, not yet built** — it
captures decisions made on 2026-06-02 so work can resume later from a
fixed plan.

## Why a Herd

One cow is one vantage point: one IP, one ASN, one geography. The value
of a herd is not "more probes" — it is **cross-vantage correlation**,
signal that a single sensor cannot produce no matter how long it runs:

- **Fan-out** — how many distinct cows a given source IP hit, and in
  what order. Hitting many cows in a short window is a broad internet
  sweep; hitting one is targeted, random, or range-specific. This single
  dimension reclassifies most of the morning report.
- **Sensor diversity** — scanners that only probe certain clouds,
  regions, or RIR allocations only appear if *our* sensors live in those
  ranges. A cow in AWS, one in a cheap EU host, and one in APNIC space
  see materially different traffic.
- **Campaign-onset timing** — watching a new CVE-shape probe ripple
  across N vantage points gives the time-to-recon metric the
  CVE-signature taxonomy is built around.

## Constraints

These shaped every decision below:

- **Own VPSes only.** We can SSH into every cow; no third-party trust
  problem.
- **Small and churny.** 3 cows now, with occasional month-long
  spin-ups or provider moves. Build and teardown must be repeatable and
  cheap — cattle, not pets.
- **Budget ~$24/mo** for the herd at present.
- **Full stack per cow.** Every cow runs the complete service: NS +
  UFW + HTTPS + a unique herd name. Sensor cows are not stripped-down.
- **Central collection must be fast.** The report reads local,
  pre-collected data and never blocks on a live fan-out of SSH pulls.

## Decisions

### 1. Provisioning — cloud-init user-data

A cow is born by pasting a `#cloud-config` block into the provider's
"user data" field at droplet creation. On first boot the cow
self-provisions with no interactive SSH step; teardown is destroying the
VPS. Every major provider (DigitalOcean, Vultr, Hetzner, Linode)
supports cloud-init user-data, so "move providers" stays trivial.

Cows **pull** their image from GHCR; they never build. Building on a
throwaway $4 host is slow and needs the full toolchain — publishing the
image once in CI and pulling it everywhere is the portability unlock.

```text
provider "user data" field at droplet creation
  -> #cloud-config runcmd: curl ... init-cow.sh | bash -s -- --site <id> ...
  -> install docker
  -> docker pull ghcr.io/mclose/honeycow:<tag>
  -> render .env (HONEY_SITE_ID, PUBLIC_IP autodetect, sinkhole=self, abuse addr)
  -> ufw route allow 53, 80, 443
  -> docker compose up -d   (caddy self-issues the cert on first request)
```

New artifact: `tools/init-cow.sh`.

### 2. Certificates — HTTP-01, zero secrets on the cow

Each cow self-issues its own certificate for
`<site>.herd.honeycow.net` via Caddy over HTTP-01. No BIND or TSIG keys
ever land on a throwaway VPS — the best hygiene for ephemeral drones.

The flagship's CAA pins issuance to **DNS-01 only**, and CAA walks down
the tree, so the herd subtree needs its own looser record:

```text
herd.honeycow.net.  CAA  0 issue "letsencrypt.org; validationmethods=http-01"
```

The flagship's `honeycow.net` CAA stays DNS-01-only and unchanged. The
`herd.honeycow.net` delegation already exists as the designated bluff
playground, so naming reuses it.

**Known tradeoff:** every `*.herd.honeycow.net` certificate appears in
Certificate Transparency logs, so a CT-watching adversary can cluster
the sensors as one operator. This is accepted on budget grounds —
per-cow throwaway domains would defeat the clustering but cost money and
wiring per cow, which the budget does not allow. Most scanners are too
unsophisticated to correlate; the property is documented, not mitigated.

**Per-cow DNS (operator step):** HTTP-01 validates against the cow's
hostname, so before (or shortly after) a cow boots, point its name at its
public IP — zero secrets on the cow means it can't self-register:

```text
<site>.herd.honeycow.net.  A     <cow-ipv4>
<site>.herd.honeycow.net.  AAAA  <cow-ipv6>   ; if the cow has v6
```

Caddy retries issuance until the name resolves, so a slight ordering race
between boot and the DNS edit is self-healing.

**Implemented (cow runtime):** `docker-compose.cow.yml` (build-less,
pulls the pinned `HONEY_IMAGE`, honey-ns + Caddy only — no DNS-01 sidecar,
no wire-monitoring) and `caddy/Caddyfile.cow` (HTTP-01 self-issuance for
`{$HERD_FQDN}`, everything proxied to the honey-ns closer). The cow's
`.env` and config files are rendered by `tools/init-cow.sh` (next).

### 3. Telemetry — edge map-reduce

Each cow keeps its **full verbose `events.jsonl` locally** (capture
wide, drill down on demand). It runs the classifier **at the edge** and
ships only a compact rolled-up digest. The collector concatenates
digests; the report merges them. Raw never leaves a cow unless we
deliberately drill into something.

This is the answer to the "central collection must be fast" constraint,
twice over: the shipped artifact is O(unique source IPs per hour), not
O(events), and the report sums pre-classified buckets instead of
re-parsing millions of raw lines. Report runtime is then flat with
respect to herd size and never blocks on a dead or slow cow.

```text
cow: full raw events.jsonl  ── kept local, capture wide, drill-down only
        |
   edge classifier (shared lib)
        |
   hourly digest.jsonl line  ── map
        |  rsync --append-verify  (ships only new lines)  every ~5 min
        |  forced-command rrsync key, chroot /herd/incoming, write own file only
        v
   FLAGSHIP collector  /herd/incoming/<site_id>.jsonl
        |  report host pulls /herd once
        v
   morning_report.py --herd  ── reduce: merge digests, render
```

#### Collector placement

The collector is the **flagship HoneyCow VPS**, not the workstation
where the report is normally run. That workstation is critical and not
disposable; giving throwaway cows SSH access into it is the wrong blast
radius. The flagship is already exposed honeypot-adjacent infra. Cows
ship to it via a **forced-command `rrsync` key** chrooted to
`/herd/incoming/`, write-only to their own `<site_id>.jsonl`. A
compromised cow can corrupt only its own digest, nothing else. The
report host pulls the whole `/herd` directory from the flagship once
(small delta), then reads locally.

#### Digest schema (Standard detail)

One JSON line per cow per hour, appended to `digest.jsonl`:

```json
{ "site_id":"eu-hel1", "bucket":"2026-06-02T13:00Z", "schema":1,
  "totals":{"events":312,"dns":240,"dns_external":31,"drops":7,"http":61,"ufw":880},
  "v4v6":{"dns_v4":29,"dns_v6":2,"http_v4":60,"http_v6":1},
  "families":{"open-resolver-canary":25,"chaos-banner":3,"cve-2026-5946-trigger":1},
  "by_src":{ "204.76.203.15":{"dns":5,"http":0,"ufw":12,
              "families":{"open-resolver-canary":5},
              "qtypes":{"A":3,"TXT":2},"qclasses":{"IN":5},
              "ufw_ports":{"udp/123":1,"udp/161":1,"udp/3702":1},
              "first":"...:14Z","last":"...:51Z"} },
  "http_paths":{"/":18,"/.env":6}, "http_uas":{"libredtail-http":4},
  "exemplars":[ { "<full raw event for a CVE-trigger / novel / oversized shape>": "..." } ] }
```

- `by_src` is the correlation backbone — merging it across cows by IP
  yields the fan-out metric directly. Size scales with unique-IP count
  (hundreds per hour), not event count.
- `exemplars` carries a few raw records for *notable* shapes (CVE
  triggers, oversized QR=1 inbound, novel qtypes) so the report can show
  real packets without a drill-down round trip.
- Hourly buckets let any report window of one hour or more be computed
  by summing buckets, and keep the shipped file append-only so
  `rsync --append-verify` transfers only new lines.

## Shared-Code Requirement

The classifier must run on the cow, so the parse-and-classify core is
extracted out of `tools/morning_report.py` into a shared library,
`tools/honeycow_digest.py`, used by **both** the cow-side digest emitter
and the central `morning_report.py --herd` merge. Same classifier, two
ends. Re-scoring against the CVE-signature taxonomy still works against
the raw retained on each cow.

## Artifacts

| Artifact | Where | Purpose |
| --- | --- | --- |
| `HONEY_SITE_ID` | `.env` + `honey_logging.py` | Per-cow attribution; stamped on every event. Backward compatible. |
| GHCR build-push job | CI workflow | Publish the image so cows pull, never build. |
| `tools/init-cow.sh` | repo | Cloud-init payload: docker + pull + `.env` + cert + up. |
| `herd.honeycow.net` CAA | BIND zone | Permit HTTP-01 so cows self-issue. |
| Per-site Caddy TLS | `caddy/Caddyfile` | Auto-issue `<site>.herd.honeycow.net`. |
| `rrsync` collector key | flagship | Forced-command, chrooted, write-own-file-only. |
| Ship cron | `tools/init-cow.sh` | `rsync --append-verify` every ~5 min. |
| `tools/honeycow_digest.py` | repo | Shared parse/classify + digest emit + merge. |
| `tools/cows.txt` | repo (gitignored) | Inventory for report enrichment; like `tools/our-ips.txt`. |
| `make report --herd` | `Makefile` | Multi-digest ingest + cross-cow sections. |

## New Report Sections

The herd unlocks sections a single cow cannot produce:

- **Fan-out** — per source IP, the count of distinct cows hit, ordered
  by spread. Broad-sweep vs targeted classifier.
- **Per-cow totals** — traffic volume and family mix at each vantage.
- **All-cows vs single-cow** — partition sources seen everywhere from
  sources seen at exactly one cow.
- **Per-cow header** — ASN / region from the inventory.

## Build Order

Each step is verifiable before any new VPS is stood up:

1. **Shared lib + `HONEY_SITE_ID` + digest emitter + `--herd` merge.**
   *(Done — `tools/honeycow_digest.py`, `make digest`, `make report-herd`.)*
   Tested against the flagship's existing raw log treated as a one-cow
   herd. Correctness gate met: a report built from the *digest*
   reproduces the *direct-from-raw* report's totals and family counts —
   a losslessness check for the dimensions the digest keeps.
2. **GHCR image in CI.** *(Done — `.github/workflows/image.yml` builds on
   PR, publishes `ghcr.io/<owner>/honeycow:{latest,sha-<short>}` on merge
   to main; linux/amd64; public package. Cows set `HONEY_IMAGE` to a
   pinned SHA tag.)* One-time manual step: flip the GHCR package to public
   after the first push.
3. **`init-cow.sh` + CAA record + per-site Caddy cert.** Stand up cow
   #2 and confirm it self-provisions and self-certs.
4. **`rrsync` collector + ship cron.** Wire telemetry; confirm
   `--append-verify` deltas and flat report time.

Step 1 is the keystone — pure code, no new infra — and de-risks the
rest. All code lands via branch -> PR -> CI -> merge, and every
committed artifact stays host-agnostic (real values live in the
gitignored `.env`).
