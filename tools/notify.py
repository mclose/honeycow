#!/usr/bin/env python3
"""Push what needs a human; stay silent otherwise.

    venv/bin/python -m tools.notify --dry-run
    venv/bin/python -m tools.notify            # last step of refresh-index.sh

Replaces the weekday "Run the Morning Report" nag, which asked the operator to
go and look. This looks for him, and only speaks when there is something:

  * DAY: each newly settled day that graded yellow or red, once, with the
    reasons the rubric recorded and the first line of the day's note.
  * HEALTH: any unattended job that failed or went stale, pushed when the set
    of problems changes and re-sent weekly while it persists.
  * DIGEST: Mondays (Chicago), one summary of the past week — colours, notes
    coverage, pcaps promoted, scanner ranges added — so a quiet week still
    proves the pipeline is alive. Silence alone would be indistinguishable
    from a dead notifier.

State lives in `<analysis>/state/notify.json`; every message is idempotent
against it. The notifier itself is watched from outside (cowmon's
`hc_ingest` freshness), since a dead refresh timer takes this down with it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    from tools import dashboard as dash
    from tools import ops
except ImportError:  # pragma: no cover
    import dashboard as dash  # type: ignore[no-redef]
    import ops  # type: ignore[no-redef]

CHICAGO = ZoneInfo("America/Chicago")
DAY_LOOKBACK = 3            # settled days considered for a DAY push
HEALTH_REMIND = timedelta(days=7)
DIGEST_HOUR = 6             # first run at/after 06:00 Chicago on Monday

# job -> max age before it counts as stale. Weekly jobs get a day of slack.
STALE = {
    "scanner_refresh": timedelta(days=8),
    "pcap_promote": timedelta(hours=26),
}
RUMINATE_LOG = Path.home() / "ruminate-weekly.log"
_RUMINATE_DONE = re.compile(
    r"^(\S+) weekly-scan: done — promoted=(\d+) .*failed=(\d+) .*taxonomy=(\d+)")


def _parse_ts(s: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def ruminate_status(log: Path = RUMINATE_LOG) -> dict | None:
    """ruminate runs from cron and only writes a log; read its last summary."""
    try:
        lines = log.read_text(errors="replace").splitlines()[-400:]
    except OSError:
        return None
    for line in reversed(lines):
        if m := _RUMINATE_DONE.match(line):
            return {"last_run": m.group(1), "ok": m.group(3) == "0",
                    "promoted": int(m.group(2)), "taxonomy": int(m.group(4))}
    return {"last_run": "", "ok": False, "error": "no completed weekly-scan in log"}


def health_problems(now: datetime, statuses: dict[str, dict | None],
                    annot: dict) -> list[str]:
    probs: list[str] = []
    stale = {**STALE, "ruminate": timedelta(days=8)}
    for job, st in statuses.items():
        if st is None:
            probs.append(f"{job}: has never reported")
            continue
        ts = _parse_ts(st.get("last_run", ""))
        if not ts or now - ts > stale.get(job, timedelta(days=2)):
            probs.append(f"{job}: last ran {st.get('last_run') or 'never'}")
        if st.get("ok") is False:
            probs.append(f"{job}: {st.get('error') or 'failed'}")
        if st.get("held"):
            probs.append(f"{job}: held — {st['held']}")
    if annot.get("ok") is False:
        probs.append(f"annotator: {annot.get('error') or 'last run failed'}")
    if len(annot.get("missing") or []) > 14:
        # a backlog that is draining is normal after a rubric change; one this
        # size that persists a week will re-trigger via the weekly reminder
        probs.append(f"annotator: {len(annot['missing'])} graded days have no note")
    return probs


def day_message(d: dict, dash_url: str | None) -> tuple[str, str]:
    title = f"HoneyCow {d['date']}: {d['status'].upper()}"
    lines = [f"• {w}" for w in d["why"][:4]]
    narr = d.get("narrative") or {}
    # A stale note argues about a colour the day no longer has; skip it rather
    # than push a contradiction. The annotator will rewrite it.
    if narr.get("text") and not narr.get("stale"):
        first = re.sub(r"\*\*", "", narr["text"]).split("\n", 1)[0]
        lines.append(f"\nNote ({narr.get('model') or 'human'}, not a measurement): "
                     f"{first[:400]}")
    if dash_url:
        lines.append(f"\n{dash_url}")
    return title, "\n".join(lines)


def digest_message(days: list[dict], extras: list[str], dash_url: str | None,
                   ) -> tuple[str, str]:
    icon = {"green": "🟩", "yellow": "🟨", "red": "🟥"}
    strip = "".join(icon.get(d["status"], "⬜") for d in days)
    counts = {s: sum(d["status"] == s for d in days) for s in icon}
    title = f"HoneyCow week: {strip}"
    body = [f"{days[0]['date']} → {days[-1]['date']}: "
            f"{counts['green']} green, {counts['yellow']} yellow, {counts['red']} red"]
    body += [f"• {d['date']} {d['status']}: {d['why'][0]}" for d in days
             if d["status"] != "green"]
    body += extras
    if dash_url:
        body.append(dash_url)
    return title, "\n".join(body)


def _week_extras(now: datetime) -> list[str]:
    out: list[str] = []
    since = now - timedelta(days=7)
    ledger = ops.state_dir() / "pcap_promotions.jsonl"
    if ledger.is_file():
        n = 0
        for line in ledger.read_text().splitlines():
            try:
                if (_parse_ts(json.loads(line)["ts"]) or since) > since:
                    n += 1
            except (json.JSONDecodeError, KeyError):
                continue
        out.append(f"pcaps promoted to keep/: {n}")
    if (sr := ops.read_status("scanner_refresh")) and sr.get("added"):
        out.append(f"scanner ranges added last run: {len(sr['added'])}")
    if rs := ruminate_status():
        out.append(f"ruminate: taxonomy={rs.get('taxonomy', '?')}, "
                   f"promoted {rs.get('promoted', 0)} last scan")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Push HoneyCow findings and health.")
    ap.add_argument("--dry-run", action="store_true", help="print, push nothing, save nothing")
    ap.add_argument("--db", type=Path, default=ops.analysis_dir() / "honeycow.db")
    ap.add_argument("--notes", type=Path, default=ops.analysis_dir() / "notes")
    args = ap.parse_args(argv)

    now = datetime.now(UTC)
    state_path = ops.state_dir() / "notify.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        state = {}
    first_run = not state
    pushed_days: set[str] = set(state.get("pushed_days", []))
    dash_url = ops.setting("HONEYCOW_DASH_URL")
    sent = 0

    data = dash.build(args.db, args.notes)
    settled = [d for d in data["days"] if not d.get("partial")
               and d["date"] < now.strftime("%Y-%m-%d")]

    # DAY pushes. On the very first run, mark history as seen rather than
    # replaying months of yellows.
    for d in settled[-DAY_LOOKBACK:]:
        if d["date"] in pushed_days:
            continue
        if d["status"] != "green" and not first_run:
            sent += ops.push(*day_message(d, dash_url), dry_run=args.dry_run)
        pushed_days.add(d["date"])

    # HEALTH
    statuses = {job: ops.read_status(job) for job in STALE}
    statuses["ruminate"] = ruminate_status()
    annot = dash.annotator_health(data["days"], args.notes)
    probs = health_problems(now, statuses, annot)
    key = "|".join(sorted(probs))
    last_alert = _parse_ts(state.get("health_alert_at", ""))
    if probs and (key != state.get("health_key")
                  or not last_alert or now - last_alert > HEALTH_REMIND):
        sent += ops.push(f"HoneyCow: {len(probs)} pipeline problem(s)",
                         "\n".join(f"• {p}" for p in probs), dry_run=args.dry_run)
        state["health_alert_at"] = now.isoformat(timespec="seconds")
    elif not probs and state.get("health_key"):
        sent += ops.push("HoneyCow: pipeline healthy again",
                         "All unattended jobs reporting normally.", dry_run=args.dry_run)
    state["health_key"] = key

    # DIGEST
    local = now.astimezone(CHICAGO)
    week = f"{local.isocalendar().year}-W{local.isocalendar().week:02d}"
    if (local.weekday() == 0 and local.hour >= DIGEST_HOUR
            and state.get("digest_week") != week and settled):
        cutoff = (local.date() - timedelta(days=7)).isoformat()
        week_days = [d for d in settled if d["date"] >= cutoff]
        if week_days:
            sent += ops.push(*digest_message(week_days, _week_extras(now), dash_url),
                             dry_run=args.dry_run)
            state["digest_week"] = week

    state["pushed_days"] = sorted(d for d in pushed_days
                                  if d >= (date.today() - timedelta(days=30)).isoformat())
    state["last_run"] = now.isoformat(timespec="seconds")
    if args.dry_run:
        print(f"[dry-run] {sent} message(s); problems: {probs or 'none'}")
        return 0
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    tmp.replace(state_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
