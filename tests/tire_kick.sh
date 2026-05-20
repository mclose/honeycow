#!/usr/bin/env bash
# tire_kick.sh — end-to-end validation against a live honeycow deployment.
#
# Issues a battery of probes across v4/v6, UDP/TCP, bluff/REFUSED/CHAOS,
# and HTTP, then pulls the matching events from the container's JSONL
# event log and asserts each probe was handled the expected way.
#
# Usage:
#   HOST4=<ipv4> HOST6=<ipv6> [REMOTE=<ssh-host>] tests/tire_kick.sh
#
# If REMOTE is unset, the script reads the event log via `docker exec`
# on the local docker daemon. If REMOTE is set (e.g. REMOTE=honeycow),
# the script ssh's to that host first.
#
# HOST6 may be empty — v6 probes are then skipped and counted as
# "n/a", not failed.
#
# Exit status: 0 if every probe passed, 1 otherwise.

set -euo pipefail

HOST4="${HOST4:-127.0.0.1}"
HOST6="${HOST6:-}"
REMOTE="${REMOTE:-}"
NONCE="$(date +%s)"
DIG_BASE="dig +time=3 +tries=1"

# ---- helpers -------------------------------------------------------------

pass=0; fail=0; skip=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
ng()   { printf '  \033[31m✗\033[0m %s — %s\n' "$1" "$2"; fail=$((fail+1)); }
note() { printf '  \033[33m·\033[0m %s — %s\n' "$1" "$2"; skip=$((skip+1)); }

fetch_events() {
    local cmd="docker exec honeycow tail -300 /var/log/honeycow/events.jsonl"
    if [ -n "$REMOTE" ]; then
        ssh "$REMOTE" "$cmd"
    else
        $cmd
    fi
}

# Find the most recent event matching a jq filter. Echoes the matching
# event JSON or empty.
find_event() {
    local filter="$1"
    echo "$events" | jq -c "select($filter)" 2>/dev/null | tail -1
}

# Family check: returns "v4" or "v6" for an IP string.
ip_family() {
    case "$1" in
        *:*) echo v6 ;;
        *)   echo v4 ;;
    esac
}

check_dns() {
    local label="$1" filter="$2" want_handler="$3" want_rcode="$4" want_family="$5"
    local event
    event="$(find_event "$filter")"
    if [ -z "$event" ]; then
        ng "$label" "no event matched filter: $filter"; return
    fi
    local got_handler got_rcode got_src got_family
    got_handler=$(echo "$event" | jq -r '.handler')
    got_rcode=$(echo "$event"   | jq -r '.rcode')
    got_src=$(echo "$event"     | jq -r '.src_ip')
    got_family=$(ip_family "$got_src")
    if [ "$got_handler" != "$want_handler" ]; then
        ng "$label" "handler=$got_handler (want $want_handler)"; return
    fi
    if [ "$got_rcode" != "$want_rcode" ]; then
        ng "$label" "rcode=$got_rcode (want $want_rcode)"; return
    fi
    if [ "$want_family" != "any" ] && [ "$got_family" != "$want_family" ]; then
        ng "$label" "src=$got_src (want $want_family family)"; return
    fi
    ok "$label"
}

check_explainer() {
    # The explainer at https://honeycow.net is served by Caddy with
    # `templates` enabled. We can't correlate to events.jsonl (Caddy
    # doesn't log there), so this is a body-content-only check.
    local label="$1" body_file="$2"
    if [ ! -s "$body_file" ]; then
        ng "$label" "response body file empty/missing"; return
    fi
    if grep -q "{{" "$body_file"; then
        ng "$label" "body has unrendered template tags (Caddy templates not enabled?)"; return
    fi
    if ! grep -q "Welcome to the pasture" "$body_file"; then
        ng "$label" "body missing cowsay welcome marker"; return
    fi
    if ! grep -q "What we refuse" "$body_file"; then
        ng "$label" "body missing 'What we refuse' section marker"; return
    fi
    # The heartbeat comment confirms the template engine actually ran AND
    # the render is fresh (not a stale cached copy). Tolerate 60s clock
    # skew between probe host and server.
    local heartbeat
    heartbeat="$(grep -oE 'rendered at [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z' "$body_file" | head -1 | sed 's/rendered at //')"
    if [ -z "$heartbeat" ]; then
        ng "$label" "no ISO-8601 heartbeat marker in body"; return
    fi
    local heartbeat_epoch now_epoch age
    heartbeat_epoch=$(date -u -d "$heartbeat" +%s 2>/dev/null) || heartbeat_epoch=0
    now_epoch=$(date -u +%s)
    age=$((now_epoch - heartbeat_epoch))
    if [ "$age" -gt 60 ] || [ "$age" -lt -60 ]; then
        ng "$label" "heartbeat ${age}s off from now (cached / clock skew / stale deploy?)"; return
    fi
    ok "$label"
}

check_http() {
    local label="$1" host_header="$2" body_file="$3"
    local event
    event="$(find_event ".event==\"http_closer\" and .host==\"$host_header\"")"
    if [ -z "$event" ]; then
        ng "$label" "no http_closer event with Host=$host_header"; return
    fi
    local resp_bytes
    resp_bytes=$(echo "$event" | jq -r '.response_bytes')
    if [ "$resp_bytes" -le 0 ] 2>/dev/null; then
        ng "$label" "response_bytes=$resp_bytes (want > 0)"; return
    fi
    if [ ! -s "$body_file" ]; then
        ng "$label" "response body file empty/missing"; return
    fi
    # Body markers: would have caught the "compose up without --build"
    # silent-no-deploy bug that bit us on PR #8.
    if ! grep -q "Welcome to the pasture" "$body_file"; then
        ng "$label" "body missing cowsay welcome marker"; return
    fi
    if ! grep -q "observably not an open resolver" "$body_file"; then
        ng "$label" "body missing 'observably not an open resolver' marker"; return
    fi
    # Templating must have substituted the placeholders.
    if grep -qE "\{client_ip\}|\{cowsay_block\}" "$body_file"; then
        ng "$label" "body contains unsubstituted placeholder"; return
    fi
    ok "$label"
}

# ---- issue probes --------------------------------------------------------

echo "==> tire_kick — host4=$HOST4 host6=${HOST6:-(skipped)} remote=${REMOTE:-(local)}"
echo "    nonce=$NONCE"
echo

# Unique qnames per probe so we can find them by name in events.jsonl.
Q_V4_UDP_BLUFF="kick-${NONCE}-v4u-bluff.tld"
Q_V6_UDP_BLUFF="kick-${NONCE}-v6u-bluff.tld"
Q_V4_TCP_BLUFF="kick-${NONCE}-v4t-bluff.tld"
Q_V6_TCP_BLUFF="kick-${NONCE}-v6t-bluff.tld"
Q_V4_UDP_EXEMPT="kick-${NONCE}-v4u-exempt.dnsscan.shadowserver.org"
Q_V4_UDP_RESERVED="kick-${NONCE}-v4u-reserved.example.com"
Q_V4_TCP_AXFR="kick-${NONCE}-v4t-axfr.tld"
Q_V4_TCP_IXFR="kick-${NONCE}-v4t-ixfr.tld"
Q_V4_UDP_META="kick-${NONCE}-v4u-meta.tld"
Q_V4_UDP_HESIOD="kick-${NONCE}-v4u-hesiod.tld"
Q_V4_UDP_SOA="kick-${NONCE}-v4u-soa.tld"
HTTP_HOST="kick-${NONCE}.tire-kick.invalid"
HTTP_BODY="$(mktemp -t tire-kick-closer.XXXXXX)"
EXPLAINER_BODY="$(mktemp -t tire-kick-explainer.XXXXXX)"
trap 'rm -f "$HTTP_BODY" "$EXPLAINER_BODY"' EXIT

echo "==> Issuing probes"
$DIG_BASE @"$HOST4" +short A "$Q_V4_UDP_BLUFF" > /dev/null || true
echo "  v4 UDP bluff:        $Q_V4_UDP_BLUFF"

if [ -n "$HOST6" ]; then
    $DIG_BASE @"$HOST6" +short A "$Q_V6_UDP_BLUFF" > /dev/null || true
    echo "  v6 UDP bluff:        $Q_V6_UDP_BLUFF"
else
    echo "  v6 UDP bluff:        SKIPPED (HOST6 unset)"
fi

$DIG_BASE @"$HOST4" +tcp +short A "$Q_V4_TCP_BLUFF" > /dev/null || true
echo "  v4 TCP bluff:        $Q_V4_TCP_BLUFF"

if [ -n "$HOST6" ]; then
    $DIG_BASE @"$HOST6" +tcp +short A "$Q_V6_TCP_BLUFF" > /dev/null || true
    echo "  v6 TCP bluff:        $Q_V6_TCP_BLUFF"
else
    echo "  v6 TCP bluff:        SKIPPED (HOST6 unset)"
fi

$DIG_BASE @"$HOST4" +short A "$Q_V4_UDP_EXEMPT" > /dev/null || true
echo "  v4 UDP exempt:       $Q_V4_UDP_EXEMPT"

$DIG_BASE @"$HOST4" +short A "$Q_V4_UDP_RESERVED" > /dev/null || true
echo "  v4 UDP reserved:     $Q_V4_UDP_RESERVED"

$DIG_BASE @"$HOST4" +tcp +short AXFR "$Q_V4_TCP_AXFR" > /dev/null || true
echo "  v4 TCP AXFR:         $Q_V4_TCP_AXFR"

# IXFR shares the refused_xfr dispatch arm with AXFR — test it
# independently so a future refactor that splits the arm doesn't
# silently regress IXFR.
$DIG_BASE @"$HOST4" +tcp +short ixfr=0 "$Q_V4_TCP_IXFR" > /dev/null || true
echo "  v4 TCP IXFR:         $Q_V4_TCP_IXFR"

# Meta-qtype FORMERR. MAILA (254) is officially obsolete but is one of
# the meta types dispatch refuses with FORMERR per RFC 6895.
$DIG_BASE @"$HOST4" +short -t MAILA "$Q_V4_UDP_META" > /dev/null || true
echo "  v4 UDP meta MAILA:   $Q_V4_UDP_META"

# Non-IN, non-CH class → REFUSED via refused_class arm. CHAOS is the
# bluffed exception; HESIOD (class 4) tests the actual refusal path.
$DIG_BASE @"$HOST4" +short -c HS A "$Q_V4_UDP_HESIOD" > /dev/null || true
echo "  v4 UDP class HS:     $Q_V4_UDP_HESIOD"

$DIG_BASE @"$HOST4" +short SOA "$Q_V4_UDP_SOA" > /dev/null || true
echo "  v4 UDP SOA:          $Q_V4_UDP_SOA"

# CHAOS version.bind has a fixed qname; correlate by timestamp instead
# of name.
chaos_ts="$(date -u +%Y-%m-%dT%H:%M:%S)"
$DIG_BASE @"$HOST4" +short -c CH -t TXT version.bind > /dev/null || true
echo "  v4 UDP CHAOS:        version.bind (CH TXT)"

# HTTP closer probe via Caddy (port 80) with a unique Host header.
# Save the response body for content assertions (cowsay marker, etc).
curl -s -o "$HTTP_BODY" -m 3 -H "Host: $HTTP_HOST" "http://$HOST4/" || true
echo "  HTTP closer:         Host=$HTTP_HOST"

# HTTPS explainer probe via Caddy on port 443 with the real honeycow.net
# Host header (so Caddy routes to the templated explainer, not the
# reverse-proxy-to-honey-ns catch-all). --resolve forces the IP without
# DNS; -k skips cert verification so the probe doesn't depend on a
# trusted CA chain.
curl -sk --resolve "honeycow.net:443:$HOST4" -o "$EXPLAINER_BODY" -m 3 \
    "https://honeycow.net/" || true
echo "  HTTPS explainer:     https://honeycow.net/ (via $HOST4)"

echo

# Brief pause so the JSONL flush settles.
sleep 1

# ---- fetch + assert ------------------------------------------------------

echo "==> Assertions (against events.jsonl on container)"
events="$(fetch_events)"

check_dns "v4 UDP bluff"  ".qname==\"${Q_V4_UDP_BLUFF}.\" and .transport==\"udp\"" \
    "synth_a" "NOERROR" "v4"

if [ -n "$HOST6" ]; then
    check_dns "v6 UDP bluff"  ".qname==\"${Q_V6_UDP_BLUFF}.\" and .transport==\"udp\"" \
        "synth_a" "NOERROR" "v6"
else
    note "v6 UDP bluff" "HOST6 unset"
fi

check_dns "v4 TCP bluff"  ".qname==\"${Q_V4_TCP_BLUFF}.\" and .transport==\"tcp\"" \
    "synth_a" "NOERROR" "v4"

if [ -n "$HOST6" ]; then
    check_dns "v6 TCP bluff"  ".qname==\"${Q_V6_TCP_BLUFF}.\" and .transport==\"tcp\"" \
        "synth_a" "NOERROR" "v6"
else
    note "v6 TCP bluff" "HOST6 unset"
fi

check_dns "v4 UDP exempt" ".qname==\"${Q_V4_UDP_EXEMPT}.\"" \
    "exempt" "REFUSED" "v4"

check_dns "v4 UDP reserved" ".qname==\"${Q_V4_UDP_RESERVED}.\"" \
    "exempt" "REFUSED" "v4"

check_dns "v4 TCP AXFR" ".qname==\"${Q_V4_TCP_AXFR}.\" and .qtype_name==\"AXFR\"" \
    "refused_xfr" "REFUSED" "v4"

check_dns "v4 TCP IXFR" ".qname==\"${Q_V4_TCP_IXFR}.\" and .qtype_name==\"IXFR\"" \
    "refused_xfr" "REFUSED" "v4"

check_dns "v4 UDP meta MAILA" ".qname==\"${Q_V4_UDP_META}.\" and .qtype_name==\"MAILA\"" \
    "formerr_meta_qtype" "FORMERR" "v4"

check_dns "v4 UDP class HS" ".qname==\"${Q_V4_UDP_HESIOD}.\" and .qclass_name==\"HS\"" \
    "refused_class" "REFUSED" "v4"

check_dns "v4 UDP SOA"    ".qname==\"${Q_V4_UDP_SOA}.\" and .qtype_name==\"SOA\"" \
    "synth_soa" "NOERROR" "v4"

# CHAOS: find the most recent version.bind query at-or-after our timestamp.
event="$(find_event ".qname==\"version.bind.\" and .qclass_name==\"CH\" and .ts>=\"${chaos_ts}\"")"
if [ -z "$event" ]; then
    ng "v4 UDP CHAOS version.bind" "no recent CH TXT event"
else
    got_rcode=$(echo "$event" | jq -r '.rcode')
    if [ "$got_rcode" != "NOERROR" ]; then
        ng "v4 UDP CHAOS version.bind" "rcode=$got_rcode (want NOERROR)"
    else
        ok "v4 UDP CHAOS version.bind"
    fi
fi

check_http "HTTP closer" "$HTTP_HOST" "$HTTP_BODY"

check_explainer "HTTPS explainer" "$EXPLAINER_BODY"

# ---- summary -------------------------------------------------------------

echo
echo "==> summary: $pass passed, $fail failed, $skip skipped"

if [ "$fail" -gt 0 ]; then exit 1; fi
exit 0
