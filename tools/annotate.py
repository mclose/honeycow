#!/usr/bin/env python3
"""Write a retrospective analyst note for every settled non-green day.

Runs on the REPORT host between `ingest` and `dashboard`. For each complete
day the rubric graded yellow or red and that has no note yet, it assembles an
evidence bundle from the SQLite index, asks a Claude model to interpret it,
and drops the prose into `<notes>/YYYY-MM-DD.md` — the slot `dashboard.py`
already renders.

    tools/annotate.py --db ~/honeycow-analysis/honeycow.db \
        --notes ~/honeycow-analysis/notes --dry-run

WHY THIS EXISTS. The dashboard detects; it does not interpret. Grades stay
deterministic and this tool NEVER feeds them — it only fills the narrative
panel, clearly labelled with the model that wrote it. Colour is still earned
by counted evidence; the note is the "so what", written after the verdict is
already in.

DESIGN CONSTRAINT: the operator will not look at this for weeks. So nothing
here may depend on being remembered — no queue to drain, no gate to pass —
and every failure has to be visible on the page rather than in a log nobody
reads. `_status.json` records the last run; the dashboard separately counts
non-green days that never got a note, which is the signal that survives this
tool being completely dead.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

try:
    from tools.dashboard import EXPLOIT_FAMILIES, RUBRIC, build
except ImportError:
    from dashboard import EXPLOIT_FAMILIES, RUBRIC, build

# Opus for the cross-day pattern work that justifies the call at all —
# "same tooling as 07-16", "this is a measurement study, not recon". Fires
# roughly once every six days, so volume is not the constraint; judgement is.
DEFAULT_MODEL = "claude-opus-5"
ENV_FILE = ".env.analysis"
STATUS_FILE = "_status.json"

SYSTEM_PROMPT = """\
You are the analyst for HoneyCow, an NS-squatting DNS honeypot on a single \
VPS. It answers every DNS query for every zone with synthesized \
authoritative-looking records, REFUSES names on an exemption list, and serves \
one static catch-all page over HTTP on port 80 to anything that connects. It \
is a passive observer: it sees recon and fingerprinting, never exploitation. \
Nothing it hosts is real, so nothing here is ever a compromise of the host.

A deterministic rubric has already graded one day yellow or red. You are \
writing the retrospective note that explains what actually happened, for an \
operator who may not read it for weeks.

Rules:
- Reason ONLY from the evidence bundle. Never invent an IP, ASN, path, \
user-agent, CVE or count that is not in it. If attribution needs data you \
were not given, say what you would need.
- `rubric_inputs` holds the exact values the rubric consumed. Use them as-is. \
Never re-derive a rule's input by summing the family breakdowns — those \
categories do not map onto the rule's inputs, and a confident claim that a \
rule misfired is worse than saying nothing. Before asserting a threshold \
should have fired, check it against `rubric_inputs.thresholds`.
- Lead with what happened, in one sentence a tired reader gets on first pass.
- Say plainly when the grade is a FALSE POSITIVE — a measurement study, a \
research scanner, a routine crawler. That is the single most valuable thing \
you can report, because it is what stops the calendar from training the \
operator to ignore colour. Name the rubric rule that misfired and, if you can, \
what would fix it.
- Prefer recurrence over novelty: if the prior-days context shows the same \
tooling, user-agent or path signature before, say so and give the dates and \
the interval. A campaign returning on a cadence is worth more than one loud day.
- Distinguish "aimed at us" from "aimed at the whole v4 internet". Almost all \
of it is the latter; say so when it is.
- No recommendations to harden, patch or block unless the evidence supports a \
specific, concrete change. This host is meant to be probed.

Write 120-220 words of plain prose. No headings, no bullet lists, no preamble, \
no sign-off. Markdown emphasis is fine. Start with the finding."""


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _rows(conn: sqlite3.Connection, sql: str, args: tuple) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args)]


def gather_evidence(conn: sqlite3.Connection, day: dict, prior: list[dict]) -> dict:
    """Assemble the day's rows behind each fired rule, plus recurrence context.

    Deliberately wider than the day card: the card is what drove colour, this
    is what a human would go pull manually before writing the same note.
    """
    d = day["date"]
    ev: dict = {
        "date": d,
        "status": day["status"],
        "rules_that_fired": day["why"],
        "baseline_28d": day["baseline"],
        "counts": {
            "dns_queries": day["dns_queries"],
            "dns_drops": day["dns_drops"],
            "http_requests": day["http"],
            "ufw_blocked": day["ufw"],
            "new_source_ips": day["new_sources"],
        },
        # NOT DNS-only: dashboard.build() folds HTTP client IPs into the same
        # `sources` map. Labelling it "dns" made a note hedge about a source
        # whose count was really its HTTP volume. Name it for what it is.
        "top_sources_all_protocols": day["sources"],
        "dns_families": day["families"],
        "http_families": day["http_families"],
        "top_http_paths": day["http_paths"],
        "top_user_agents": day["user_agents"],
        # The exact values the rubric consumed. Without these the model
        # re-derives them from the family breakdown and gets them wrong —
        # `env-harvest` looks exploit-shaped but is deliberately NOT in
        # EXPLOIT_FAMILIES, which produced a confident false claim that a rule
        # had misfired. Authoritative inputs beat plausible arithmetic.
        "rubric_inputs": {
            "exploit_probes_counted": day["exploit"],
            "exploit_families_counted": list(EXPLOIT_FAMILIES),
            "note": ("only the families listed above count toward the exploit "
                     "rule; env-harvest and other probe families do not"),
            "cve_trigger_queries_counted": day["cve_trigger"],
            "qr_oversized_nonresearch": day["qr_oversized_nonresearch"],
            "thresholds": RUBRIC,
        },
    }

    ev["http_talkers"] = _rows(conn, """
        SELECT client_ip, COUNT(*) requests, COUNT(DISTINCT path) distinct_paths,
               MIN(ts) first_seen, MAX(ts) last_seen,
               (julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0 span_s
        FROM http WHERE substr(ts,1,10)=?
        GROUP BY client_ip ORDER BY requests DESC LIMIT 8""", (d,))

    # Which UA each talker used — the join that makes recurrence detectable.
    # Ranked WITHIN each client: a global top-N is a sample of the busiest
    # pairs, which silently misrepresents a loud talker that rotates UAs.
    ev["talker_user_agents"] = _rows(conn, """
        SELECT client_ip, user_agent, n FROM (
            SELECT client_ip, user_agent, COUNT(*) n,
                   ROW_NUMBER() OVER (PARTITION BY client_ip ORDER BY COUNT(*) DESC) rk
            FROM http WHERE substr(ts,1,10)=? AND user_agent IS NOT NULL
            GROUP BY client_ip, user_agent)
        WHERE rk <= 4 AND client_ip IN (
            SELECT client_ip FROM http WHERE substr(ts,1,10)=?
            GROUP BY client_ip ORDER BY COUNT(*) DESC LIMIT 5)
        ORDER BY n DESC""", (d, d))

    # How many distinct identities each loud talker wore. A single client
    # cycling unrelated UA strings is a signature in itself.
    ev["talker_ua_diversity"] = _rows(conn, """
        SELECT client_ip, COUNT(DISTINCT user_agent) distinct_user_agents,
               COUNT(*) requests
        FROM http WHERE substr(ts,1,10)=?
        GROUP BY client_ip ORDER BY requests DESC LIMIT 5""", (d,))

    fired = " ".join(day["why"]).lower()

    if "exploit-shaped" in fired:
        marks = ",".join("?" * len(EXPLOIT_FAMILIES))
        ev["exploit_probes"] = _rows(conn, f"""
            SELECT client_ip, family, user_agent, COUNT(*) n FROM http
            WHERE substr(ts,1,10)=? AND family IN ({marks})
            GROUP BY client_ip, family ORDER BY n DESC LIMIT 20""",
            (d, *EXPLOIT_FAMILIES))

    if "cve-" in fired:
        ev["cve_trigger_queries"] = _rows(conn, """
            SELECT src_ip, qclass, qtype, COUNT(*) n,
                   COUNT(DISTINCT qname) distinct_qnames, MIN(qname) example_qname,
                   MIN(ts) first_seen, MAX(ts) last_seen
            FROM dns WHERE substr(ts,1,10)=? AND family='cve-2026-5946-trigger'
            GROUP BY src_ip, qclass, qtype ORDER BY n DESC LIMIT 20""", (d,))

    if day["reflection_bursts"]:
        ev["reflection_bursts"] = day["reflection_bursts"][:5]

    if "never-before-seen" in fired:
        ev["new_source_note"] = (
            f"{day['new_sources']} IPs first seen on this day "
            f"(baseline {day['baseline']['new_sources']}/day)"
        )

    if "dns volume" in fired:
        ev["dns_talkers"] = _rows(conn, """
            SELECT src_ip, qtype, qclass, COUNT(*) n, COUNT(DISTINCT qname) distinct_qnames,
                   (julianday(MAX(ts)) - julianday(MIN(ts))) * 86400.0 span_s
            FROM dns WHERE substr(ts,1,10)=? AND event='query'
            GROUP BY src_ip, qtype, qclass ORDER BY n DESC LIMIT 10""", (d,))

    # Recurrence context: prior non-green days with their loudest signature,
    # so "we have seen this tool before" is answerable from the bundle alone.
    ctx = []
    for p in prior[-90:]:
        if p["status"] == "green":
            continue
        ctx.append({
            "date": p["date"], "status": p["status"], "why": p["why"][0],
            "top_user_agent": p["user_agents"][0][0] if p["user_agents"] else None,
            "top_source_any_protocol": p["sources"][0][0] if p["sources"] else None,
            "http": p["http"], "dns_queries": p["dns_queries"],
        })
    ev["prior_non_green_days"] = ctx[-14:]
    return ev


def load_cve_context(taxonomy_dir: Path | None) -> list[dict]:
    """Promoted ruminate signatures, so the model knows what we listen for.

    Best-effort: a missing or unparseable taxonomy must never block a note.
    """
    if not taxonomy_dir or not taxonomy_dir.is_dir():
        return []
    out = []
    for p in sorted(taxonomy_dir.glob("*.yaml")):
        fields = {}
        for line in p.read_text(errors="replace").splitlines():
            if line.startswith((" ", "-", "#")) or ":" not in line:
                continue
            k, _, v = line.partition(":")
            if k.strip() in ("id", "title", "axis", "confidence", "summary"):
                fields[k.strip()] = v.strip().strip("\"'")
        if fields:
            fields.setdefault("id", p.stem)
            out.append(fields)
    return out


def render_note(text: str, model: str, status: str) -> str:
    """Frontmatter carries provenance so the page can label it as model-written."""
    stamp = datetime.now(tz=UTC).isoformat(timespec="seconds")
    return (
        "---\n"
        "source: model\n"
        f"model: {model}\n"
        f"generated: {stamp}\n"
        f"status: {status}\n"
        "---\n"
        f"{text.strip()}\n"
    )


def annotate_day(client, model: str, evidence: dict, cve_context: list[dict]) -> str:
    bundle = {"evidence": evidence, "cve_signatures_we_match": cve_context}
    resp = client.messages.create(
        model=model,
        max_tokens=4000,
        system=[{"type": "text", "text": SYSTEM_PROMPT,
                 "cache_control": {"type": "ephemeral"}}],
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        messages=[{"role": "user", "content":
                   "Evidence bundle for the graded day:\n\n"
                   + json.dumps(bundle, indent=1, sort_keys=True, default=str)}],
    )
    if resp.stop_reason == "refusal":
        raise RuntimeError(f"model declined: {resp.stop_details}")
    text = "".join(b.text for b in resp.content if b.type == "text").strip()
    if not text:
        raise RuntimeError(f"empty response (stop_reason={resp.stop_reason})")
    return text


def _client(api_key: str | None):
    import anthropic
    return anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()


def _api_key(repo_root: Path) -> str | None:
    """Env var first, then the gitignored `.env.analysis`.

    Deliberately NOT the main `.env`: that file is the honeypot's identity
    config and its sibling lives on the public-facing VPS. An API key has no
    business in a file whose whole job is to be deployed to a machine we
    invite strangers to probe. Separate file, separate blast radius.
    """
    if key := os.environ.get("ANTHROPIC_API_KEY"):
        return key
    env_file = repo_root / ENV_FILE
    if env_file.is_file():
        for line in env_file.read_text(errors="replace").splitlines():
            k, _, v = line.partition("=")
            if k.strip() == "ANTHROPIC_API_KEY":
                return v.strip().strip("\"'") or None
    return None


def select_days(data: dict, notes_dir: Path, force: bool, only: str | None) -> list[dict]:
    """Settled, non-green, not already written. Retrospective by construction:
    `partial` excludes today, so the earliest candidate is yesterday."""
    out = []
    for day in data["days"]:
        if only and day["date"] != only:
            continue
        if day["partial"] or day["status"] == "green":
            continue
        if not force and (notes_dir / f"{day['date']}.md").exists():
            continue
        out.append(day)
    return out


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(
        description="Write model-authored notes for settled non-green days.")
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--notes", required=True, type=Path)
    ap.add_argument("--model", default=os.environ.get("HONEYCOW_ANNOTATE_MODEL", DEFAULT_MODEL))
    ap.add_argument("--taxonomy", type=Path,
                    default=Path(os.environ.get("HONEYCOW_CVE_TAXONOMY",
                                                Path.home() / "projects/ruminate/taxonomy")),
                    help="ruminate taxonomy/ dir, used as context (optional)")
    ap.add_argument("--max-days", type=int, default=5,
                    help="cap API calls per run so a rebuild can't fan out")
    ap.add_argument("--day", help="annotate only this YYYY-MM-DD")
    ap.add_argument("--force", action="store_true", help="rewrite existing notes")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be written; no API call, no writes")
    args = ap.parse_args(argv)

    data = build(args.db)
    candidates = select_days(data, args.notes, args.force, args.day)
    over_cap = max(0, len(candidates) - args.max_days)
    candidates = candidates[-args.max_days:] if args.max_days > 0 else candidates

    if not candidates:
        print("no settled non-green days need a note", file=sys.stderr)
        if not args.dry_run:
            _write_status(args.notes, args.model, [], None, 0)
        return 0

    conn = _connect(args.db)
    by_date = {d["date"]: i for i, d in enumerate(data["days"])}
    cve_context = load_cve_context(args.taxonomy)

    if args.dry_run:
        for day in candidates:
            ev = gather_evidence(conn, day, data["days"][:by_date[day["date"]]])
            size = len(json.dumps(ev, default=str))
            print(f"[dry-run] would annotate {day['date']} {day['status'].upper()} "
                  f"via {args.model} — bundle {size / 1024:.1f} KB, "
                  f"{len(day['why'])} rule(s) fired, {len(cve_context)} CVE signature(s)")
            print(f"          -> {args.notes / (day['date'] + '.md')}")
        if over_cap:
            print(f"[dry-run] {over_cap} older day(s) skipped by --max-days {args.max_days}",
                  file=sys.stderr)
        conn.close()
        return 0

    key = _api_key(repo_root)
    args.notes.mkdir(parents=True, exist_ok=True)
    written, error = [], None
    try:
        client = _client(key)
    except Exception as exc:  # noqa: BLE001 — must land in _status.json, not a traceback
        _write_status(args.notes, args.model, [], f"client init failed: {exc}", over_cap)
        print(f"annotate: {exc}", file=sys.stderr)
        return 1

    for day in candidates:
        try:
            ev = gather_evidence(conn, day, data["days"][:by_date[day["date"]]])
            text = annotate_day(client, args.model, ev, cve_context)
            path = args.notes / f"{day['date']}.md"
            path.write_text(render_note(text, args.model, day["status"]))
            written.append(day["date"])
            print(f"wrote {path} ({len(text)} chars)", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 — one bad day must not stop the rest
            error = f"{day['date']}: {exc}"
            print(f"annotate: {error}", file=sys.stderr)

    conn.close()
    _write_status(args.notes, args.model, written, error, over_cap)
    return 1 if error else 0


def _write_status(notes: Path, model: str, written: list[str],
                  error: str | None, over_cap: int) -> None:
    notes.mkdir(parents=True, exist_ok=True)
    (notes / STATUS_FILE).write_text(json.dumps({
        "last_run": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "ok": error is None,
        "model": model,
        "written": written,
        "deferred_by_cap": over_cap,
        "error": error,
    }, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
