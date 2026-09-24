#!/usr/bin/env bash
# Pull BIND query logs from the authoritative nameservers to the report host.
#
# Runs on claude, NOT on any nameserver. Mirrors tools/pull-logs.sh in spirit:
# the raw logs are the capture-of-record and land here append-only, while the
# DuckDB index built from them stays derived and rebuildable.
#
#   tools/pull-ns-logs.sh --dry-run
#   tools/pull-ns-logs.sh
#
# WHY RSYNC AND NOT A BYTE-TAIL. honeycow's events.jsonl is append-only, so
# pull-logs.sh can tail it by offset. BIND *rotates*: queries.log becomes
# queries.log.0, .0 becomes .1, and so on. An offset into "queries.log" means
# something different after every rotation. rsync's size+mtime quick-check
# skips the rotated files (immutable once rotated) and moves only the live
# file, which BIND caps at 100 MB — compressed, a few MB per run.
#
# The files are 0640 bind:adm inside a 0750 directory, so the remote side runs
# rsync under sudo. Passwordless sudo for the pulling user is required; that is
# already how the fleet's restic and monitoring reach these paths.
set -euo pipefail

HOSTS="${HONEYCOW_NS_HOSTS:-ns1 ns2 ns3}"
ANALYSIS_DIR="${HONEYCOW_ANALYSIS_DIR:-$HOME/honeycow-analysis}"
DEST="$ANALYSIS_DIR/ns"
DRY_RUN=""

usage() { sed -n '2,20p' "$0" | sed 's/^# \?//'; exit 0; }
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN="--dry-run" ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '%s pull-ns-logs: %s\n' "$(date -Is)" "$*" >&2; }

[ -n "$DRY_RUN" ] && log "DRY RUN — no files will be written"

total_before=0
[ -d "$DEST" ] && total_before=$(du -sk "$DEST" 2>/dev/null | cut -f1)

for host in $HOSTS; do
    target="$DEST/$host"
    [ -n "$DRY_RUN" ] || mkdir -p "$target"
    log "pulling $host -> $target"
    # --ignore-existing on the rotated files would be wrong: a rotation shifts
    # content between names, so let rsync compare and re-fetch what changed.
    # Only queries.log* is taken; the other channels (dnssec, xfer, security)
    # are not what this index is for and would multiply the transfer.
    rsync -az --info=stats1 $DRY_RUN \
        --rsync-path="sudo -n rsync" \
        --include='queries.log*' \
        --include='named.log.*' \
        --exclude='*' \
        "$host:/var/log/named/" "$target/" 2>&1 | sed 's/^/    /' >&2 || {
            log "WARNING: $host failed — continuing with the others"
            continue
        }
    # The pre-true-up syslog history on ns1/ns2 lives outside /var/log/named/.
    # It is a different timestamp format (ingest_ns.py handles both) and about
    # four extra weeks. Absent on a host that was always file-based.
    rsync -az --info=stats1 $DRY_RUN \
        --rsync-path="sudo -n rsync" \
        "$host:/var/log/named.log.*" "$target/" 2>&1 | sed 's/^/    /' >&2 || true
done

if [ -z "$DRY_RUN" ]; then
    total_after=$(du -sk "$DEST" 2>/dev/null | cut -f1)
    log "done — $DEST now $(du -sh "$DEST" 2>/dev/null | cut -f1) (was $((total_before/1024)) MB)"
fi
