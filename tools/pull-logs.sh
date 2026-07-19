#!/usr/bin/env bash
#
# pull-logs.sh — INCREMENTAL fetch of the honeypot's raw logs to the report host.
#
# The old approach re-copied the whole events.jsonl (~150 MB and growing) plus
# every ufw rotation every night — ~1.5% of the transfer was actually new. Both
# logs are append-only, so we ship only the delta:
#
#   * events.jsonl — pull just the new tail (bytes past what we already have).
#     The local file size IS the offset, so there is no state file to corrupt.
#   * ufw.log*      — rsync --append-verify (the herd's chosen mechanism): the
#     growing current file sends only its delta, immutable .gz rotations are
#     skipped, and a rotation (file shrinks) self-heals via full re-transfer.
#
# The result is byte-identical to a full pull (append-only guarantees it), so
# the downstream SQLite index is unchanged. Idempotent ingest tolerates any
# overlap regardless.
#
#   tools/pull-logs.sh                # incremental
#   tools/pull-logs.sh --dry-run      # show deltas, fetch nothing
#   tools/pull-logs.sh --full         # ignore offsets, re-pull everything
#
set -euo pipefail

VPS="${VPS_HOST:-honeycow}"
DIR="${ANALYSIS_DIR:-$HOME/honeycow-analysis}"
CONTAINER="${HONEY_CONTAINER:-honeycow}"
REMOTE_EVENTS="/var/log/honeycow/events.jsonl"

DRY_RUN=0
FULL=0
for a in "$@"; do
    case "$a" in
        --dry-run) DRY_RUN=1 ;;
        --full)    FULL=1 ;;
        *) echo "unknown arg: $a" >&2; exit 2 ;;
    esac
done

mkdir -p "$DIR" "$DIR/ufw-raw"
EVENTS="$DIR/events.jsonl"

# --- events.jsonl: append-only, pull only the new tail ----------------------
# The file lives INSIDE the container, so the path must be an argument (a
# `< file` redirect would resolve on the docker host, not in the container).
# shellcheck disable=SC2029  # $CONTAINER/$REMOTE_EVENTS are ours; expand locally
remote_size=$(ssh "$VPS" "docker exec $CONTAINER wc -c $REMOTE_EVENTS" | awk '{print $1}')
local_size=0
{ [ "$FULL" -eq 0 ] && [ -f "$EVENTS" ]; } && local_size=$(wc -c < "$EVENTS")

if [ "$remote_size" -lt "$local_size" ]; then
    echo "events.jsonl shrank on VPS (rotated/reset) — will re-pull in full"
    local_size=0
fi
delta=$((remote_size - local_size))

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] events.jsonl: have ${local_size}B, remote ${remote_size}B" \
         "-> would fetch ${delta}B"
else
    if [ "$local_size" -eq 0 ]; then
        : > "$EVENTS"   # truncate for a full (re)pull
    fi
    if [ "$delta" -gt 0 ]; then
        tmp="$DIR/.events.delta"
        # Fetch to a temp first: an interrupted transfer leaves EVENTS intact,
        # so the next run recomputes the same offset and retries cleanly.
        # shellcheck disable=SC2029  # offset/container/path are ours; expand locally
        ssh "$VPS" "docker exec $CONTAINER tail -c +$((local_size + 1)) $REMOTE_EVENTS" > "$tmp"
        cat "$tmp" >> "$EVENTS"
        rm -f "$tmp"
    fi
    echo "events: +${delta}B ($(wc -l < "$EVENTS") lines total)"
fi

# --- ufw.log*: rsync only the changed bytes, then recombine for ingest -------
# sudo on the remote reads the syslog-owned files; fall back to plain rsync
# (works if the invoking user can already read them).
rsync_ufw() {
    local extra=("$@")
    rsync -a --append-verify "${extra[@]}" --rsync-path="sudo rsync" \
        "$VPS:/var/log/ufw.log*" "$DIR/ufw-raw/" 2>/dev/null || \
    rsync -a --append-verify "${extra[@]}" \
        "$VPS:/var/log/ufw.log*" "$DIR/ufw-raw/"
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[dry-run] ufw.log*: rsync --append-verify (transfers only changed bytes):"
    rsync_ufw --dry-run --stats 2>/dev/null | grep -E 'Number of|Total transferred' \
        | sed 's/^/    /' || true
else
    [ "$FULL" -eq 1 ] && rm -f "$DIR"/ufw-raw/ufw.log*
    rsync_ufw
    # Recombine oldest-first (local only, no network) into the file ingest reads.
    # shellcheck disable=SC2046  # deliberate word-split: multiple rotation files
    ( cd "$DIR/ufw-raw" && zcat -f $(ls -tr ufw.log*) ) > "$DIR/ufw.log"
    echo "ufw: $(wc -l < "$DIR/ufw.log") lines total"
fi
