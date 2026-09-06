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
    log "[dry-run] would run: make -C $REPO_DIR annotate ANALYSIS_DIR=$ANALYSIS_DIR"
    log "[dry-run] would run: make -C $REPO_DIR dashboard ANALYSIS_DIR=$ANALYSIS_DIR"
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
# Interpret the settled yellow/red days before rendering, so a new note lands
# on the page in the same pass. Non-fatal on purpose: a failed API call must
# still leave a rendered dashboard, and the page itself reports the gap (the
# annotator writes _status.json; the dashboard counts un-annotated graded days).
make -C "$REPO_DIR" annotate ANALYSIS_DIR="$ANALYSIS_DIR" \
    || log "annotate failed — see $ANALYSIS_DIR/notes/_status.json"
# Render straight into the directory caddy-claude serves. No copy step: the
# SQLite index and the web server are both on this host.
make -C "$REPO_DIR" dashboard ANALYSIS_DIR="$ANALYSIS_DIR"
log "done"
