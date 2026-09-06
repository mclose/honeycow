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
- **`-W` does not give tcpdump a ring buffer.** `-W` only overwrites in
  conjunction with `-C` (size-based rotation); with `-G` it caps the file
  count and *exits at the limit*, and strftime tokens in `-w` mean every
  file is uniquely named so nothing is overwritten anyway. Our
  `-G 3600 -W 168` looked like a 7-day ring and was actually an unbounded
  writer with a 7-day exit/restart tic. Nothing pruned the pcap volume from
  2026-05-20 until it hit 14 GB and took the disk to 90% (2026-08-26).
  Retention now lives in `wire-cleanup` (zeek 7d, pcaps 14d) — the one
  place that bounds either volume. If you add another capture volume,
  give it to `wire-cleanup` at the same time or it will grow forever.
- **`/pcaps/keep/` is exempt from pruning.** `wire-cleanup` uses
  `-maxdepth 1`, so a pcap promoted into `keep/` is held indefinitely. That
  is the escape hatch that makes 14-day retention safe: when the morning
  report finds something worth the raw bytes, copy that hour in before it
  ages out. Keep the set small and deliberate — it is the only pcap data
  worth backing up. (`backup-prep.sh` on the VPS deliberately excludes the
  rotating pcaps; it stages `honeycow_logs`, zeek, caddy/acme and `/etc`.)
- **Caddy + acme are mandatory, not opt-in.** honeycow.net needs HTTPS
  (Caddy terminates TLS) and honeycow itself can't (and shouldn't) terminate
  TLS. The merged `docker-compose.prod.yml` reflects this. There is no
  separate `docker-compose.caddy.yml` anymore.
- **Compose `${VAR:-default}` shadows the Python default.** Every tunable
  lives in up to four places: the constant in `honey_ns.py`, `.env.example`,
  `docker-compose.yml` and `docker-compose.cow.yml`. Compose injects them as
  `${HONEY_X:-<literal>}`, so whenever a var is absent from `.env` — and ours
  are **commented out** — the *compose* fallback wins and the Python constant
  is never read. Commented-out in `.env` looks like "the code default
  applies"; it means the opposite. Changing only `honey_ns.py` changes
  nothing in a containerized deploy. This cost a deploy on 2026-08-26: the
  UDP rate limit went 200 -> 20, CI was green, `make deploy` succeeded, and a
  live 80-query burst came back 80/80 answered because compose was still
  injecting 200. `tests/test_deployment_files.py` now pins the compose and
  `.env.example` values to the `honey_ns` constants, so they fail loudly
  instead of drifting — keep that pin in place when adding a new tunable.
- **Verify behaviour changes by exercising them, not by reading the constant
  back.** In the incident above, `docker exec honeycow python3 -c "import
  honey_ns; print(...)"` cheerfully printed `20.0` while the running process
  used 200 — importing the module reads the file on disk, not the live
  config. `docker exec honeycow printenv` shows what the process actually
  got, and a real burst against `HONEY_PUBLIC_A` shows what it actually does.
  Prefer the burst. Related: `make smoke` proves the synth path is alive, not
  that a limit or threshold has the value you think.
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
- **`requirements.txt` builds the honeypot image; `requirements-analysis.txt`
  does not.** `requirements.txt` is pip-compiled into `requirements.lock`,
  which the Dockerfile installs — so anything added there ships to the VPS and
  bloats a container that is deliberately minimal, read-only and offline. The
  report-host tools (`annotate.py` needs the `anthropic` SDK) go in
  `requirements-analysis.txt`, which only `make venv` / `make install` read.
  Never let an analysis dependency reach the lock file.

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
- `tools/morning_report.py` — daily traffic summary. Also announces new CVE
  signatures: `ruminate`'s weekly scan auto-promotes drafted signatures into
  `taxonomy/` and appends them to `state/promotions.jsonl`, which the report
  reads (`--promotions`, best-effort — a missing or malformed file must never
  cost you the report). Promotion is automatic because the manual review gate
  stalled: 44 drafts, 1 promotion, May→Sep 2026. The real gate belongs at
  *consumption* — when the signature matcher lands and taxonomy entries start
  driving day colour, it must match only entries marked confirmed. Three input
  modes:
  `--events` (raw JSONL), `--db` (the SQLite index, the default for
  `make report`), `--herd` (merged per-site digests). See [[morning-report]]
  feedback in agent memory.
- `tools/pull-logs.sh` — **incremental** fetch of the raw logs from the VPS:
  byte-tail of the append-only `events.jsonl` + `rsync --append-verify` of
  `ufw.log*`. Byte-identical to a full pull; ships ~140 KB instead of 237 MB.
- `tools/ingest.py` — builds the SQLite analysis index. Idempotent via a
  per-row `rowhash`, so re-ingesting overlapping data never double-counts.
- `tools/dashboard.py` + `dashboard_template.html` — renders the daily-watch
  page. The grading rubric is one config block at the top of the script.
- `tools/annotate.py` — retrospective analyst note for every settled non-green
  day, via the Anthropic API (Opus by default). Idempotent (skips days that
  already have a note), capped with `--max-days` so a rebuild can't fan out,
  and `--dry-run` costs nothing. Key comes from `ANTHROPIC_API_KEY` or the
  gitignored `.env.analysis` — deliberately NOT the honeypot's `.env`, whose
  sibling lives on the public VPS.
- `tools/refresh-index.sh` — pull + ingest + annotate + render, under a
  lockfile. What the systemd timer runs (`deploy/systemd/`). The annotate step
  is non-fatal: a failed API call must still leave a rendered dashboard.

## Analysis pipeline (runs on claude, NOT the honeypot)

The raw logs live on the honeycow VPS; analysis runs on the report host and
pulls them down. `make refresh` = `pull` → `ingest` → `annotate` → `dashboard`,
fired 4-hourly by a systemd **user** timer anchored to America/Chicago.

    make pull       # incremental: only the new delta crosses the wire
    make ingest     # (re)build ~/honeycow-analysis/honeycow.db
    make report     # fast report from the index (report-raw reads raw files)
    make annotate   # model notes for settled yellow/red days (DRY_RUN=1 first)
    make dashboard  # render to ~/www/honeycow-dash, served by caddy-claude
                    # at honeycow.lab.deflationhollow.net (tailnet-only)

Rules that matter here:

- **The JSONL is the capture-of-record; the DB is a derived, rebuildable
  index.** If it is ever wrong, `make ingest REBUILD=1`. Never treat the DB
  as the source of truth.
- **The data dir is persistent** (`~/honeycow-analysis`, never `/tmp`). The
  DB accumulates, so its UFW history outlives the VPS's ~5-week rotation.
- **The dashboard detects; it does not interpret.** Counts and grades are
  computed and never inferred. Interpretation lives in a separate per-day slot
  (`--notes`) that **never feeds a grade**. `tools/annotate.py` fills that slot
  automatically for settled yellow/red days via the Anthropic API, and every
  such note is stamped with the model that wrote it and rendered with a
  "written by <model>, not a measurement" byline. A note may be wrong; a count
  may not. Keep that boundary — the moment a narrative can move a colour, the
  calendar stops being evidence.
- **Nothing in the analysis pipeline may depend on being remembered.** The
  operator will not look at this for weeks at a time, so there is no queue to
  drain and no gate to pass: notes are written and published automatically.
  The corollary is that failures must be visible *on the page*, not in a
  journal. `annotator_health()` reports both what the annotator said about its
  last run (`notes/_status.json`) and — independently — how many graded days
  have no interpretation, computed from the data so it stays true even when
  the annotator is completely dead.
- **Colour grades deviation, the detail panel shows everything.** A routine
  signal must not drive colour, or the calendar trains you to ignore it.

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
