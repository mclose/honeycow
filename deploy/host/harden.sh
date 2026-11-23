#!/usr/bin/env bash
# Host-level hardening for a honeycow VPS. Idempotent; safe to re-run.
#
#   sudo deploy/host/harden.sh --dry-run            # show every change, make none
#   sudo deploy/host/harden.sh                      # apply all parts
#   sudo deploy/host/harden.sh --only swap,sysctl   # apply some parts
#   sudo deploy/host/harden.sh --remove-firewall    # take the firewall block out
#
# Parts:
#   swap      1 GiB /swapfile + fstab entry. Without swap, memory pressure on a
#             1 GB box means thrashing on file pages (load in the tens, ssh
#             unusable) long before the OOM killer acts.
#   sysctl    /etc/sysctl.d/90-honeycow.conf: low swappiness; a conntrack table
#             big enough that a SYN burst can't fill it (at 8192, "table full,
#             dropping packet" drops every new connection, ours included); host
#             listeners get the same SYN-ACK settings as the containers (see
#             docker-compose.yml).
#   firewall  A per-source cap on concurrent half-open TCP to 53/80/443, inside
#             ufw-docker's block in /etc/ufw/after.rules + after6.rules (a rule
#             added to DOCKER-USER directly is wiped by `ufw reload`).
#             connlimit counts a source's live conntrack entries, and closed /
#             TIME_WAIT ones don't count. A spoofed source never completes a
#             handshake, so its count climbs and it is capped. A real scanner
#             completes and closes each connection and never gets near the cap
#             (rig: 4119 conn/s from one source, 0 failures). Logged as
#             "[UFW HALFOPEN CAP]" so it lands in ufw.log and the index.
set -euo pipefail

SWAPFILE=/swapfile
SWAP_SIZE=1G
SYSCTL_FILE=/etc/sysctl.d/90-honeycow.conf
MODULES_FILE=/etc/modules-load.d/honeycow.conf
RULES4=/etc/ufw/after.rules
RULES6=/etc/ufw/after6.rules
HALFOPEN_CAP=256          # concurrent half-open+open conns per source
BEGIN='# BEGIN HONEYCOW HALF-OPEN CAP'
END='# END HONEYCOW HALF-OPEN CAP'

DRY=0; ONLY="swap,sysctl,firewall"; REMOVE_FW=0
usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --only) shift; [ $# -gt 0 ] || usage 2; ONLY="$1" ;;
    --remove-firewall) REMOVE_FW=1; ONLY="firewall" ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
  shift
done
case ",$ONLY," in *[!a-z,]*) echo "bad --only: $ONLY" >&2; exit 2 ;; esac
for p in ${ONLY//,/ }; do
  case "$p" in swap|sysctl|firewall) ;; *) echo "unknown part: $p" >&2; exit 2 ;; esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
want() { case ",$ONLY," in *",$1,"*) return 0 ;; esac; return 1; }
say() { if [ "$DRY" -eq 1 ]; then echo "[dry-run] $*"; else echo "$*"; fi; }

do_swap() {
  if swapon --show=NAME --noheadings | grep -qx "$SWAPFILE"; then
    echo "swap: $SWAPFILE already active"
  else
    [ -e "$SWAPFILE" ] && { echo "swap: $SWAPFILE exists but is not active; refusing to touch it" >&2; return 1; }
    say "swap: create $SWAP_SIZE $SWAPFILE, mkswap, swapon"
    if [ "$DRY" -eq 0 ]; then
      fallocate -l "$SWAP_SIZE" "$SWAPFILE"; chmod 600 "$SWAPFILE"
      mkswap "$SWAPFILE" >/dev/null; swapon "$SWAPFILE"
    fi
  fi
  if grep -qE "^${SWAPFILE}[[:space:]]" /etc/fstab; then
    echo "swap: fstab entry present"
  else
    say "swap: append '$SWAPFILE none swap sw 0 0' to /etc/fstab"
    [ "$DRY" -eq 1 ] || echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  fi
}

write_if_changed() {  # path, content
  if [ -f "$1" ] && [ "$(cat "$1")" = "$2" ]; then echo "$1: unchanged"; return 1; fi
  say "$1: write"; if [ "$DRY" -eq 1 ]; then diff <(cat "$1" 2>/dev/null) <(echo "$2") || true; return 1; fi
  printf '%s\n' "$2" > "$1"; return 0
}

do_sysctl() {
  write_if_changed "$MODULES_FILE" "nf_conntrack" || true
  [ "$DRY" -eq 1 ] || modprobe nf_conntrack
  local conf
  conf=$(cat <<'EOF'
# honeycow: managed by deploy/host/harden.sh
vm.swappiness = 10
net.netfilter.nf_conntrack_max = 65536
net.ipv4.tcp_syncookies = 2
net.ipv4.tcp_synack_retries = 1
EOF
)
  write_if_changed "$SYSCTL_FILE" "$conf" || true
  if [ "$DRY" -eq 0 ]; then sysctl -q -p "$SYSCTL_FILE"; fi
  echo "sysctl: live $(sysctl -n vm.swappiness) swappiness, conntrack_max $(sysctl -n net.netfilter.nf_conntrack_max)," \
       "syncookies $(sysctl -n net.ipv4.tcp_syncookies), synack_retries $(sysctl -n net.ipv4.tcp_synack_retries)"
}

fw_block() {  # family: 4|6
  local chain mask
  if [ "$1" = 4 ]; then chain=honeycow-halfopen; mask=32
  else chain=honeycow6-halfopen; mask=64; fi
  cat <<EOF
$BEGIN
:$chain - [0:0]
-A DOCKER-USER -p tcp -m multiport --dports 53,80,443 --syn -m connlimit --connlimit-above $HALFOPEN_CAP --connlimit-mask $mask -j $chain
-A $chain -m limit --limit 6/min --limit-burst 10 -j LOG --log-prefix "[UFW HALFOPEN CAP] "
-A $chain -j DROP
$END
EOF
}

render_rules() {  # file family -> stdout: file with our block removed, then (unless removing) inserted
  local anchor; [ "$2" = 4 ] && anchor='-A DOCKER-USER -j ufw-user-forward' || anchor='-A DOCKER-USER -j ufw6-user-forward'
  grep -qxF -- "$anchor" "$1" || { echo "$1: anchor '$anchor' not found (is ufw-docker installed?)" >&2; return 1; }
  awk -v b="$BEGIN" -v e="$END" -v a="$anchor" -v blk="$3" '
    $0 == b { skip = 1; next } $0 == e { skip = 0; next } skip { next }
    $0 == a && blk != "" { print blk } { print }' "$1"
}

do_firewall() {
  local changed=0 f fam new tool
  for fam in 4 6; do
    if [ "$fam" = 4 ]; then f=$RULES4; tool=iptables-restore; else f=$RULES6; tool=ip6tables-restore; fi
    local blk=""; [ "$REMOVE_FW" -eq 1 ] || blk=$(fw_block "$fam")
    new=$(render_rules "$f" "$fam" "$blk")
    if [ "$new" = "$(cat "$f")" ]; then echo "$f: unchanged"; continue; fi
    say "$f: update"; diff <(cat "$f") <(echo "$new") || true
    # Validate the whole candidate file before ufw ever sees it.
    echo "$new" | "$tool" -n --test || { echo "$f: candidate failed $tool --test; not written" >&2; return 1; }
    if [ "$DRY" -eq 0 ]; then
      cp -a "$f" "$f.honeycow-bak.$(date -u +%Y%m%dT%H%M%SZ)"
      printf '%s\n' "$new" > "$f"; changed=1
    fi
  done
  if [ "$changed" -eq 1 ]; then ufw reload; fi
  if [ "$DRY" -eq 0 ]; then
    iptables -S DOCKER-USER | grep -c connlimit | sed 's/^/firewall: v4 connlimit rules live: /'
    ip6tables -S DOCKER-USER | grep -c connlimit | sed 's/^/firewall: v6 connlimit rules live: /'
  fi
}

want swap && do_swap
want sysctl && do_sysctl
want firewall && do_firewall
exit 0
