#!/usr/bin/env bash
# Pull query logs from the authoritative nameservers to the report host:
# BIND on ns1-3, PowerDNS on pdns-nyc2.
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
# something different after every rotation, so rsync compares by name and
# re-fetches whatever changed.
#
# ONLY THE NEWEST THREE FILES. BIND keeps 20 x 100 MB per host, and mirroring
# all of them held 4.6 GB on the report host that the DuckDB index already
# holds. The mirror is a staging area, not an archive: ns.duckdb is the record
# (it reaches back past anything the nameservers still keep). queries.log and
# .0 carry every new row; .1 is margin for two rotations between pulls. Older
# local copies are deleted by ingest_ns.py once their rows are recorded.
#
# The files are 0640 bind:adm inside a 0750 directory, so the remote side runs
# rsync under sudo. Passwordless sudo for the pulling user is required; that is
# already how the fleet's restic and monitoring reach these paths.
#
# POWERDNS IS A JOURNAL, NOT A FILE. pdns-nyc2 logs queries into its own
# journald namespace (size-capped, see ~/projects/digitalocean/pdns-nyc2), so
# there is nothing to rsync. Instead: journalctl from a cursor saved here, only
# the "Remote ... wants" lines, in UTC, appended to one pdns-queries.<day>.log
# per UTC day. One day per file is what keeps ingest_ns.py's (host, day)
# partition replace exact: a changed file holds the whole of its day. The
# cursor is saved only after the lines are on disk, so a failed run re-pulls
# rather than skips.
set -euo pipefail

HOSTS="${HONEYCOW_NS_HOSTS:-ns1 ns2 ns3 pdns-nyc2}"
PDNS_HOSTS="${HONEYCOW_PDNS_HOSTS:-pdns-nyc2}"
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

is_pdns() { case " $PDNS_HOSTS " in *" $1 "*) return 0 ;; esac; return 1; }

pull_pdns() {
    local host="$1" target="$2" cursor="" raw
    [ -s "$target/.cursor" ] && cursor="$(cat "$target/.cursor")"
    # A journald cursor is key=value pairs of hex; anything else is corruption,
    # and it travels through a remote shell, so refuse rather than quote.
    local ok_cursor='^[a-z]=[0-9a-f]+(;[a-z]=[0-9a-f]+)*$'
    if [ -n "$cursor" ] && ! [[ "$cursor" =~ $ok_cursor ]]; then
        log "WARNING: $host: unreadable cursor in $target/.cursor, skipping"
        return 1
    fi
    local after=""
    [ -n "$cursor" ] && after="--after-cursor='$cursor'"
    raw="$(mktemp)"
    # journalctl exits 1 both when --grep matches nothing and on a real error
    # (bad cursor, no sudo). What differs is the trailing "-- cursor:" line,
    # printed whenever it read the journal at all, so that is the test.
    # shellcheck disable=SC2029  # $after is expanded here on purpose
    ssh "$host" "sudo -n env TZ=UTC journalctl --namespace=pdns --no-pager \
            -o short-iso-precise --show-cursor --grep='^Remote .* wants ' $after" \
        > "$raw" || true
    local n new_cursor
    new_cursor=$(sed -n 's/^-- cursor: //p' "$raw" | tail -1)
    if [ -z "$new_cursor" ]; then
        rm -f "$raw"
        return 1
    fi
    n=$(grep -c " wants '" "$raw" || true)
    if [ -n "$DRY_RUN" ]; then
        local from="the start of the journal"
        [ -n "$cursor" ] && from="the saved cursor"
        log "[dry-run] $host: $n new query line(s) since $from"
        rm -f "$raw"
        return 0
    fi
    # Append each line to its UTC day's file (>> in awk: plain > would truncate
    # the file on its first write of every run).
    grep " wants '" "$raw" | awk -v d="$target" '
        $1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/ {
            print >> (d "/pdns-queries." substr($1, 1, 10) ".log")
        }' || true
    printf '%s\n' "$new_cursor" > "$target/.cursor.tmp"
    mv "$target/.cursor.tmp" "$target/.cursor"
    rm -f "$raw"
    log "    $host: $n new query line(s)"
}

[ -n "$DRY_RUN" ] && log "DRY RUN — no files will be written"

total_before=0
[ -d "$DEST" ] && total_before=$(du -sk "$DEST" 2>/dev/null | cut -f1)

for host in $HOSTS; do
    target="$DEST/$host"
    [ -n "$DRY_RUN" ] || mkdir -p "$target"
    log "pulling $host -> $target"
    if is_pdns "$host"; then
        pull_pdns "$host" "$target" || log "WARNING: $host failed — continuing with the others"
        continue
    fi
    # --ignore-existing would be wrong: a rotation shifts content between
    # names, so let rsync compare and re-fetch what changed. Only the query
    # channel is taken; the others (dnssec, xfer, security) are not what this
    # index is for. The pre-2026-08-01 syslog history (named.log.*) is already
    # in the index and is no longer pulled.
    rsync -az --info=stats1 $DRY_RUN \
        --rsync-path="sudo -n rsync" \
        --include='queries.log' \
        --include='queries.log.0' \
        --include='queries.log.1' \
        --exclude='*' \
        "$host:/var/log/named/" "$target/" 2>&1 | sed 's/^/    /' >&2 || {
            log "WARNING: $host failed — continuing with the others"
            continue
        }
done

if [ -z "$DRY_RUN" ]; then
    log "done — $DEST now $(du -sh "$DEST" 2>/dev/null | cut -f1) (was $((total_before/1024)) MB)"
fi
