#!/usr/bin/env python3
"""Cross-check Zeek dns.log against honeycow events.jsonl.

Pulls both log streams from a remote VPS, counts DNS queries in each
within a time window, and surfaces deltas. A delta means honeycow's
parser/rate-limiter dropped queries that the wire saw — or vice versa,
that we're logging phantom events the wire didn't carry.

Usage:
    tools/report_wire.py --hours 24 --remote honeycow

The --remote flag tells the script which host to ssh into. If omitted,
the script assumes the honeycow + zeek containers are running on the
local docker daemon.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta


def run(cmd: list[str]) -> str:
    """Run a command, return stdout, raise on non-zero exit."""
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def fetch_events(remote: str | None, since: datetime) -> list[dict]:
    """Pull honeycow events.jsonl and parse DNS query records."""
    cmd = ["docker", "exec", "honeycow", "cat", "/var/log/honeycow/events.jsonl"]
    if remote:
        cmd = ["ssh", remote, *cmd]
    out = run(cmd)
    events = []
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event") != "query":
            continue
        ts_str = e.get("ts", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            continue
        if ts < since:
            continue
        events.append(e)
    return events


def fetch_zeek_dns(remote: str | None, since: datetime) -> list[dict]:
    """Pull Zeek dns.log entries (JSON mode) within the window."""
    # Zeek rotates hourly; concatenate today's + yesterday's dns.log.
    cmd = [
        "docker", "exec", "honeycow-zeek", "sh", "-c",
        "cat /zeek/logs/dns.log 2>/dev/null; "
        "for f in /zeek/logs/*/dns.*.log.gz; do [ -e \"$f\" ] && zcat \"$f\"; done",
    ]
    if remote:
        cmd = ["ssh", remote, *cmd]
    try:
        out = run(cmd)
    except subprocess.CalledProcessError as exc:
        print(f"[zeek] fetch failed: {exc.stderr}", file=sys.stderr)
        return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        ts_epoch = row.get("ts")
        if ts_epoch is None:
            continue
        ts = datetime.fromtimestamp(ts_epoch, tz=UTC)
        if ts < since:
            continue
        row["_ts"] = ts
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hours", type=float, default=24.0,
                    help="window size in hours (default 24)")
    ap.add_argument("--remote", type=str, default=None,
                    help="ssh host (e.g. 'honeycow'); omit for local")
    args = ap.parse_args()

    since = datetime.now(tz=UTC) - timedelta(hours=args.hours)
    print(f"== wire-vs-app report (last {args.hours:g}h, since {since.isoformat()}) ==\n")

    events = fetch_events(args.remote, since)
    zeek_rows = fetch_zeek_dns(args.remote, since)

    print("=== totals ===")
    print(f"  honeycow events.jsonl (DNS queries): {len(events)}")
    print(f"  zeek dns.log entries:                {len(zeek_rows)}")
    delta = len(zeek_rows) - len(events)
    print(f"  delta (zeek - honeycow):             {delta:+d}")

    if delta == 0:
        print("\n  Counts match — every query the wire saw shows up in honeycow's log.")
    elif delta > 0:
        print(f"\n  Zeek saw {delta} more queries than honeycow logged.")
        print("  Possible causes: rate-limited drops, parser rejections, container restart.")
    else:
        print(f"\n  Honeycow logged {-delta} more queries than zeek saw.")
        print("  Possible causes: zeek dropped packets, BPF filter mismatch, clock skew.")

    # Sample a few zeek rows for spot-checking.
    if zeek_rows:
        print("\n=== sample zeek dns.log rows (most recent 5) ===")
        for row in zeek_rows[-5:]:
            src = row.get("id.orig_h", "?")
            q = row.get("query", "?")
            qt = row.get("qtype_name", "?")
            print(f"  {row['_ts'].isoformat()}  src={src}  {qt} {q}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
