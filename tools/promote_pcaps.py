#!/usr/bin/env python3
"""Copy the pcap hours behind rare-by-nature events into `/pcaps/keep/`.

    venv/bin/python -m tools.promote_pcaps --dry-run
    venv/bin/python -m tools.promote_pcaps            # run by refresh-index.sh

`wire-cleanup` deletes pcaps after 14 days; `/pcaps/keep/` is the only escape.
Promotion used to be "when the morning report turns something up, copy that
hour in" — a manual step, which for an operator who looks every few weeks
means the raw bytes are gone before anyone asks for them.

So promotion is keyed on the same signals the rubric treats as rare by nature,
NOT on day colour (a colour can be re-graded later; the bytes cannot be
recovered):

  * reflection-shaped bursts (frozen txid + source port, >= the rubric floor),
    answered or refused;
  * oversized QR=1 packets from port 53 that are not from a research range;
  * CVE-2026-5946 trigger-shaped queries.

Idempotent (`cp -n`), capped per run, and it never copies the newest file —
that one is still being written. Each promotion is appended to
`<analysis>/state/pcap_promotions.jsonl` so the weekly digest can say what
was kept and why.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from tools import ops
    from tools.dashboard import RUBRIC
    from tools.honeycow_digest import (
        ip_in_nets,
        is_private_or_loopback,
        load_our_ips,
        load_research_cidrs,
    )
except ImportError:  # pragma: no cover
    import ops  # type: ignore[no-redef]
    from dashboard import RUBRIC  # type: ignore[no-redef]
    from honeycow_digest import (  # type: ignore[no-redef]
        ip_in_nets,
        is_private_or_loopback,
        load_our_ips,
        load_research_cidrs,
    )

JOB = "pcap_promote"
CONTAINER = "honeycow-wire-cleanup"
LOOKBACK_DAYS = 14          # wire-cleanup prunes at find -mtime +14, i.e. >= 15 days
MAX_FILES_PER_RUN = 24
_PCAP_RX = re.compile(r"^honeycow-(\d{8})-(\d{4})\.pcap$")


def trigger_events(db: Path, research_nets, our_nets,
                   days: int = LOOKBACK_DAYS) -> list[tuple[float, str]]:
    """(epoch, reason) for every moment worth keeping the raw bytes of."""
    since = (datetime.now(UTC) - timedelta(days=days)).timestamp()
    out: list[tuple[float, str]] = []

    def ours(ip: str) -> bool:
        return not ip or is_private_or_loopback(ip) or ip_in_nets(ip, our_nets)

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for ip, qtype, n, t0, t1 in conn.execute(
            "SELECT src_ip, qtype, COUNT(*), MIN(ts_epoch), MAX(ts_epoch) FROM dns "
            "WHERE ts_epoch >= ? AND event='query' AND dns_id IS NOT NULL "
            "AND src_ip IS NOT NULL GROUP BY substr(ts,1,10), src_ip, dns_id, src_port "
            "HAVING COUNT(*) >= ?", (since, RUBRIC["reflection_burst_min_packets"]),
        ):
            if ours(ip):
                continue
            why = f"reflection burst: {n} x {qtype} for {ip}"
            out += [(t0, why), (t1, why)]
        for ip, t in conn.execute(
            "SELECT src_ip, ts_epoch FROM dns WHERE ts_epoch >= ? AND "
            "drop_reason='oversized_datagram' AND src_port=53", (since,),
        ):
            if not ours(ip) and not ip_in_nets(ip, research_nets):
                out.append((t, f"oversized QR=1 from non-research {ip}"))
        for ip, t in conn.execute(
            "SELECT src_ip, ts_epoch FROM dns WHERE ts_epoch >= ? AND "
            "family='cve-2026-5946-trigger'", (since,),
        ):
            if not ours(ip):
                out.append((t, f"CVE-2026-5946 trigger from {ip}"))
    finally:
        conn.close()
    return sorted(out)


def pcap_start(name: str) -> float | None:
    m = _PCAP_RX.match(name)
    if not m:
        return None
    return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M").replace(
        tzinfo=UTC).timestamp()


def select_files(events: list[tuple[float, str]], names: list[str],
                 kept: set[str]) -> dict[str, str]:
    """file -> first reason. tcpdump `-G 3600` rotates from its START minute,
    not the top of the hour, so a file covers [its start, the next start)."""
    starts = sorted((s, n) for n in names if (s := pcap_start(n)) is not None)
    if len(starts) < 2:
        return {}
    closed = starts[:-1]  # the newest is still being written
    picks: dict[str, str] = {}
    for t, why in events:
        cover = None
        for i, (s, n) in enumerate(starts):
            if s <= t and (i + 1 == len(starts) or t < starts[i + 1][0]):
                cover = n
                break
        if cover and cover not in kept and any(n == cover for _, n in closed):
            picks.setdefault(cover, why)
    return picks


def _remote(vps: str, cmd: str, timeout: int = 120) -> str:
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", vps, cmd],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"ssh {vps}: {r.stderr.strip()[-300:]}")
    return r.stdout


def list_pcaps(vps: str) -> tuple[list[str], set[str]]:
    out = _remote(vps, f"docker exec {CONTAINER} sh -c "
                       "'ls /pcaps; echo ---KEEP---; ls /pcaps/keep 2>/dev/null'")
    top, _, keep = out.partition("---KEEP---")
    return ([n for n in top.split() if _PCAP_RX.match(n)],
            {n for n in keep.split() if _PCAP_RX.match(n)})


def promote(vps: str, names: list[str]) -> None:
    for n in names:
        if not _PCAP_RX.match(n):  # names reach a remote shell; never trust them
            raise ValueError(f"refusing odd pcap name {n!r}")
    cps = " && ".join(f"cp -n /pcaps/{n} /pcaps/keep/{n}" for n in names)
    _remote(vps, f"docker exec {CONTAINER} sh -c 'mkdir -p /pcaps/keep && {cps}'",
            timeout=600)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Promote pcaps behind rare events to keep/.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--db", type=Path, default=ops.analysis_dir() / "honeycow.db")
    ap.add_argument("--vps", default=ops.setting("VPS_HOST") or "honeycow")
    args = ap.parse_args(argv)
    status: dict = {"ok": False, "promoted": []}
    try:
        research = load_research_cidrs(ops.REPO_ROOT / "config/source_exemptions.txt")
        our = load_our_ips(ops.REPO_ROOT / "tools/our-ips.txt", [])
        events = trigger_events(args.db, research, our)
        names, kept = list_pcaps(args.vps)
        picks = select_files(events, names, kept)
        chosen = sorted(picks)[:MAX_FILES_PER_RUN]
        status.update(events=len(events), candidates=len(picks),
                      deferred=max(len(picks) - len(chosen), 0))
        for n in chosen:
            print(f"{'[dry-run] ' if args.dry_run else ''}keep {n}  <- {picks[n]}")
        if args.dry_run:
            print(f"[dry-run] {len(events)} trigger events, {len(chosen)} file(s) to keep")
            return 0
        if chosen:
            promote(args.vps, chosen)
            ledger = ops.state_dir() / "pcap_promotions.jsonl"
            with ledger.open("a") as fh:
                for n in chosen:
                    fh.write(json.dumps({"ts": ops.now_iso(), "file": n,
                                         "reason": picks[n]}) + "\n")
        status.update(ok=True, promoted=chosen)
        return 0
    except Exception as exc:  # noqa: BLE001 — record, never take down the refresh
        status["error"] = f"{type(exc).__name__}: {exc}"
        print(status["error"], file=sys.stderr)
        return 1
    finally:
        if not args.dry_run:
            ops.write_status(JOB, status)


if __name__ == "__main__":
    sys.exit(main())
