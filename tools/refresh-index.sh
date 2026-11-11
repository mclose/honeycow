#!/usr/bin/env bash
#
# refresh-index.sh — nightly pull + ingest for the HoneyCow SQLite index.
#
# Runs on the REPORT host (claude.lab.deflationhollow.net), not the honeypot.
# It SSHes into the honeycow VPS, pulls the raw events.jsonl + full rotated
# ufw.log, and updates the local SQLite index (tools/ingest.py). Because
# ingest is idempotent (rowhash PK), re-running is always safe and the DB
# accumulates history that outlives UFW's ~5-week rotation on the VPS.
#
# Wired as a systemd user timer (see deploy/systemd/). Standalone-safe too:
#     tools/refresh-index.sh              # pull + ingest into the persistent dir
#     tools/refresh-index.sh --dry-run    # show what would run, touch nothing
#
# The data dir is persistent by design (NOT /tmp, which is wiped on reboot):
#   override with HONEYCOW_ANALYSIS_DIR=/some/path tools/refresh-index.sh
#
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYSIS_DIR="${HONEYCOW_ANALYSIS_DIR:-$HOME/honeycow-analysis}"
LOCK="$ANALYSIS_DIR/.refresh.lock"

log() { printf '%s refresh-index: %s\n' "$(date -Is)" "$*"; }

mkdir -p "$ANALYSIS_DIR"

if [ "$DRY_RUN" = 1 ]; then
    log "[dry-run] repo=$REPO_DIR data=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR pull ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR ingest ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR pull-ns ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR ingest-ns ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR annotate ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR promote-pcaps ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR dashboard ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR notify ANALYSIS_DIR=$ANALYSIS_DIR"
    # ingest's own --dry-run reports new-vs-existing without writing.
    make -C "$REPO_DIR" ingest ANALYSIS_DIR="$ANALYSIS_DIR" DRY_RUN=1 || true
    exit 0
fi

# Serialize: a slow pull must never overlap the next timer firing.
exec 9>"$LOCK"
if ! flock -n 9; then
    log "another run holds $LOCK; exiting"
    exit 0
fi

log "start  repo=$REPO_DIR data=$ANALYSIS_DIR"
make -C "$REPO_DIR" pull   ANALYSIS_DIR="$ANALYSIS_DIR"
make -C "$REPO_DIR" ingest ANALYSIS_DIR="$ANALYSIS_DIR"
# The nameserver sensor (ns1-3 BIND, pdns-nyc2 PowerDNS). Ahead of annotate,
# whose evidence bundle reads it for the "a real nameserver also saw this
# source" fact. Non-fatal: it is a separate sensor, and a nameserver that is
# down or unreachable must not cost the honeypot its dashboard. Before this
# step existed the sensor was refreshed by hand and sat weeks stale.
if make -C "$REPO_DIR" pull-ns ANALYSIS_DIR="$ANALYSIS_DIR"; then
    make -C "$REPO_DIR" ingest-ns ANALYSIS_DIR="$ANALYSIS_DIR" \
        || log "ingest-ns failed — nameserver index left as it was"
else
    log "pull-ns failed — nameserver index left as it was"
fi
# Interpret the settled days before rendering, so a new note lands on the page
# in the same pass. Scope is non-green days unless HONEYCOW_ANNOTATE_ALL=1 is
# set in the environment (the systemd unit sets it) — inherited through make.
# Non-fatal on purpose: a failed API call must still leave a rendered
# dashboard, and the page itself reports the gap (the annotator writes
# _status.json; the dashboard counts un-annotated in-scope days).
make -C "$REPO_DIR" annotate ANALYSIS_DIR="$ANALYSIS_DIR" \
    || log "annotate failed — see $ANALYSIS_DIR/notes/_status.json"
# Render straight into the directory caddy-claude serves. No copy step: the
# SQLite index and the web server are both on this host.
# Raw bytes behind rare events are pruned at 14 days; save them while they
# exist. Non-fatal: a VPS hiccup must not cost the dashboard.
make -C "$REPO_DIR" promote-pcaps ANALYSIS_DIR="$ANALYSIS_DIR" \
    || log "promote-pcaps failed — see $ANALYSIS_DIR/state/pcap_promote.json"
make -C "$REPO_DIR" dashboard ANALYSIS_DIR="$ANALYSIS_DIR"
# Last, so it reports on everything above. Pushes only when there is
# something; health is computed from the status files, not remembered.
make -C "$REPO_DIR" notify ANALYSIS_DIR="$ANALYSIS_DIR" \
    || log "notify failed"
log "done"
