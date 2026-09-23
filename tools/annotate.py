#!/usr/bin/env python3
"""Write a retrospective analyst note for settled days.

Runs on the REPORT host between `ingest` and `dashboard`. For each complete
day in scope that has no current note, it assembles an evidence bundle from
the SQLite index, asks a Claude model to interpret it, and drops the prose
into `<notes>/YYYY-MM-DD.md` — the slot `dashboard.py` already renders.

Scope is non-green days by default. `--all-days` covers every settled day,
green included, which is what you want if the question is "what does an
ordinary day here look like" rather than "explain this colour". A green day
costs the same as a yellow one (~12K input tokens either way — the bundle is
mostly fixed context), so the choice is about signal, not spend.

    tools/annotate.py --db ~/honeycow-analysis/honeycow.db \
        --notes ~/honeycow-analysis/notes --dry-run
    tools/annotate.py --db ... --notes ... --all-days --max-days 30

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
import hashlib
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
# "same tooling as 07-16", "this is a measurement study, not recon". Even at
# --all-days that is one call per day, so volume is not the constraint;
# judgement is.
DEFAULT_MODEL = "claude-opus-5"
ENV_FILE = ".env.analysis"
STATUS_FILE = "_status.json"


# USD per million tokens, for the run's spend estimate only — never for a
# decision. Hardcoded rates go stale: treat the printed figure as an order of
# magnitude, and read the real number off the Anthropic console. Cache writes
# bill at 1.25x input, cache reads at 0.1x.
PRICING = {"claude-opus-5": (5.00, 25.00)}


def estimate_cost(model: str, usage) -> float | None:
    """Rough USD for one call, or None if we don't have rates for the model."""
    rates = PRICING.get(model)
    if not rates:
        return None
    rate_in, rate_out = rates
    write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    read = getattr(usage, "cache_read_input_tokens", 0) or 0
    plain = getattr(usage, "input_tokens", 0) or 0
    out = getattr(usage, "output_tokens", 0) or 0
    return ((plain * rate_in) + (write * rate_in * 1.25) + (read * rate_in * 0.1)
            + (out * rate_out)) / 1_000_000


def rubric_fingerprint() -> str:
    """Short hash of the grading config a note was written against.

    `select_days` already regenerates a note whose recorded *colour* went
    stale. That misses the commoner case: a threshold moves, the colour does
    NOT change, and the note goes on quoting a ratio the rubric no longer
    computes. 2026-07-09's note argued "6.0x the median (3,041 vs 504)" for
    weeks after the median became a breadth-adjusted 417 — still yellow, still
    wrong, and nothing could see it. Stamping the rubric makes that visible
    the same way a colour change already is.

    Deliberately the whole RUBRIC dict, not a hand-curated subset: a new
    tunable someone forgets to add to the list is exactly the kind of drift
    this is supposed to catch, and the cost of over-triggering is one
    regenerated note.
    """
    payload = json.dumps(RUBRIC, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:12]

SYSTEM_PROMPT = """\
You are the analyst for HoneyCow, an NS-squatting DNS honeypot on a single \
VPS. It answers every DNS query for every zone with synthesized \
authoritative-looking records, REFUSES names on an exemption list, and serves \
one static catch-all page over HTTP on port 80 to anything that connects. It \
is a passive observer: it sees recon and fingerprinting, never exploitation. \
Nothing it hosts is real, so nothing here is ever a compromise of the host.

A deterministic rubric has already graded one day. You are writing the \
retrospective note that explains what actually happened, for an operator who \
may not read it for weeks. The grade is already decided and your note never \
changes it — you are writing the "so what", after the verdict is in.

The day may be GREEN. A green day is not "nothing to report": it is the \
baseline this honeypot actually sits in, and describing it accurately is what \
makes a yellow mean something later. On a green day, lead with the shape of \
the ordinary traffic — who the regulars are, what they wanted — and spend the \
rest on whatever is genuinely new or drifting: tooling appearing for the \
first time, a familiar source block changing behaviour, a count trending \
toward a threshold without crossing it. If a green day is truly \
indistinguishable from the last several, say exactly that in a sentence or \
two and stop; padding a quiet day is worse than a short note.

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
what would fix it. The mirror case matters just as much on a green day: if \
something in the evidence looks genuinely notable and NO rule fired on it, \
say so and name the rule that should have.
- Prefer recurrence over novelty: if the prior-days context shows the same \
tooling, user-agent or path signature before, say so and give the dates and \
the interval. A campaign returning on a cadence is worth more than one loud day.
- Distinguish "aimed at us" from "aimed at the whole v4 internet". Almost all \
of it is the latter; say so when it is.
- No recommendations to harden, patch or block unless the evidence supports a \
specific, concrete change. This host is meant to be probed.

Write 120-220 words of plain prose — fewer on a green day with nothing to \
distinguish it. No headings, no bullet lists, no preamble, no sign-off. \
Markdown emphasis is fine. Start with the finding."""


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
            # The rule grades DEDUPLICATED probes: sources running the same
            # path-script are one behaviour, charged at their loudest copy.
            # Both numbers travel because a note that compares the raw total
            # against the baseline is making the comparison the rule
            # deliberately stopped making.
            "exploit_probes_counted": day["exploit"],
            "exploit_probes_raw": day["exploit_raw"],
            "exploit_distinct_path_scripts": day["exploit_kits"],
            "exploit_families_counted": list(EXPLOIT_FAMILIES),
            "note": ("only the families listed above count toward the exploit "
                     "rule; env-harvest and other probe families do not. "
                     "`exploit_probes_counted` is deduplicated by path-script "
                     "and is the value the threshold is applied to; "
                     "`exploit_probes_raw` is the uncollapsed count"),
            "cve_trigger_queries_counted": day["cve_trigger"],
            # Volume rules grade the day MINUS its single loudest source, and
            # the baseline is computed the same way. Do not compare the raw
            # totals against the baseline — that is the comparison the rule
            # deliberately stopped making.
            "http_excluding_busiest_source": day["http_ex_top"],
            "dns_excluding_busiest_source": day["dns_ex_top"],
            "busiest_http_source": day["http_top"],
            "busiest_dns_source": day["dns_top"],
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
            if k.strip() in ("cve_id", "vendor", "product", "vulnerability_class",
                             "axis", "confidence"):
                fields[k.strip()] = v.strip().strip("\"'")
        if fields:
            fields.setdefault("cve_id", p.stem)
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
        f"rubric: {rubric_fingerprint()}\n"
        "---\n"
        f"{text.strip()}\n"
    )


def annotate_day(client, model: str, evidence: dict,
                 cve_context: list[dict]) -> tuple[str, object]:
    """One API call, one day's note.

    The CVE signature list is identical for every day in a run and is over half
    the input, so it lives in the cached system prefix rather than the user
    message — caching is a prefix match, so stable content has to come first to
    be reusable at all. At one day per run (the 4-hourly timer) the 5-minute
    TTL has usually expired and this changes nothing; on a backfill of 30 days
    it is the difference between paying for those tokens 30 times and paying
    once. `--all-days` makes backfills the normal case.
    """
    resp = client.messages.create(
        model=model,
        max_tokens=4000,
        system=[
            {"type": "text", "text": SYSTEM_PROMPT},
            {"type": "text",
             "text": ("CVE signatures this honeypot's own responses match, as "
                      "reference. These are fingerprint surface, NOT observed "
                      "attempts:\n\n"
                      + json.dumps(cve_context, indent=1, sort_keys=True, default=str)),
             "cache_control": {"type": "ephemeral"}},
        ],
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        messages=[{"role": "user", "content":
                   "Evidence bundle for the graded day:\n\n"
                   + json.dumps(evidence, indent=1, sort_keys=True, default=str)}],
    )
    if resp.stop_reason == "refusal":
        raise RuntimeError(f"model declined: {resp.stop_details}")
    text = "".join(b.text for b in resp.content if b.type == "text").strip()
    if not text:
        raise RuntimeError(f"empty response (stop_reason={resp.stop_reason})")
    return text, resp.usage


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


def _frontmatter_field(path: Path, field: str) -> str | None:
    """One scalar from a note's frontmatter, or None."""
    if not path.is_file():
        return None
    for line in path.read_text(errors="replace").splitlines()[:8]:
        k, _, v = line.partition(":")
        if k.strip() == field:
            return v.strip()
    return None


def _note_status(path: Path) -> str | None:
    return _frontmatter_field(path, "status")


def _note_rubric(path: Path) -> str | None:
    return _frontmatter_field(path, "rubric")


def _is_model_note(path: Path) -> bool:
    return _frontmatter_field(path, "source") == "model"


def select_days(data: dict, notes_dir: Path, force: bool, only: str | None,
                all_days: bool = False) -> list[dict]:
    """Settled, in scope, and either unwritten or written against a stale rubric.

    Retrospective by construction: `partial` excludes today, so the earliest
    candidate is yesterday. Scope is non-green days unless `all_days`.

    Two staleness cases, both because the rubric is explicitly expected to be
    tweaked. The obvious one is a changed VERDICT: a day goes red -> yellow and
    its note still opens "the red is...". The quieter one is a changed RUBRIC
    with the same verdict — the note keeps quoting a ratio nothing computes any
    more (see `rubric_fingerprint`). Either mismatch means regenerate; without
    both, a threshold change leaves a trail of confidently wrong prose that
    only a human sweep could find.
    """
    current = rubric_fingerprint()
    out = []
    for day in data["days"]:
        if only and day["date"] != only:
            continue
        if day["partial"] or (day["status"] == "green" and not all_days):
            continue
        note = notes_dir / f"{day['date']}.md"
        if not force and note.exists():
            # A hand-written note is never regenerated — a person chose those
            # words, and a threshold moving is not a reason to overwrite them.
            if not _is_model_note(note):
                continue
            if _note_status(note) == day["status"] and _note_rubric(note) == current:
                continue
        out.append(day)
    return out


def prune_stale_notes(data: dict, notes_dir: Path, dry_run: bool,
                      all_days: bool = False) -> list[str]:
    """Drop MODEL-written notes for days no longer in scope.

    A rubric change can regrade a day to green, stranding a note that argues
    about a red that no longer exists. Hand-written notes are never touched:
    a human wrote that on purpose, and the day being quiet now is not a reason
    to throw their reasoning away.

    Under `--all-days` a green day's note is the point rather than an orphan,
    so nothing is pruned for being green — otherwise each run would delete the
    notes the previous run paid for and immediately rewrite them.
    """
    if not notes_dir.is_dir() or all_days:
        return []
    keep = {d["date"] for d in data["days"] if d["status"] != "green" and not d["partial"]}
    dropped = []
    for note in sorted(notes_dir.glob("*.md")):
        if note.stem in keep or not _is_model_note(note):
            continue
        dropped.append(note.stem)
        if not dry_run:
            note.unlink()
    return dropped


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
    ap.add_argument("--all-days", action="store_true",
                    default=os.environ.get("HONEYCOW_ANNOTATE_ALL") == "1",
                    help="annotate every settled day, green included "
                         "(default: non-green only). Env: HONEYCOW_ANNOTATE_ALL=1")
    ap.add_argument("--day", help="annotate only this YYYY-MM-DD")
    ap.add_argument("--force", action="store_true", help="rewrite existing notes")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be written; no API call, no writes")
    args = ap.parse_args(argv)

    data = build(args.db)
    pruned = prune_stale_notes(data, args.notes, args.dry_run, args.all_days)
    if pruned:
        print(f"{'[dry-run] would prune' if args.dry_run else 'pruned'} "
              f"{len(pruned)} note(s) for days that regraded green: "
              f"{', '.join(pruned)}", file=sys.stderr)
    candidates = select_days(data, args.notes, args.force, args.day, args.all_days)
    over_cap = max(0, len(candidates) - args.max_days)
    candidates = candidates[-args.max_days:] if args.max_days > 0 else candidates

    scope = "settled" if args.all_days else "settled non-green"
    if not candidates:
        print(f"no {scope} days need a note", file=sys.stderr)
        if not args.dry_run:
            _write_status(args.notes, args.model, [], None, 0, args.all_days)
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
        print(f"[dry-run] scope: {scope} days; {len(candidates)} to write this run",
              file=sys.stderr)
        conn.close()
        return 0

    key = _api_key(repo_root)
    args.notes.mkdir(parents=True, exist_ok=True)
    written, error = [], None
    try:
        client = _client(key)
    except Exception as exc:  # noqa: BLE001 — must land in _status.json, not a traceback
        _write_status(args.notes, args.model, [], f"client init failed: {exc}",
                      over_cap, args.all_days)
        print(f"annotate: {exc}", file=sys.stderr)
        return 1

    spend = 0.0
    for day in candidates:
        try:
            ev = gather_evidence(conn, day, data["days"][:by_date[day["date"]]])
            text, usage = annotate_day(client, args.model, ev, cve_context)
            path = args.notes / f"{day['date']}.md"
            path.write_text(render_note(text, args.model, day["status"]))
            written.append(day["date"])
            cost = estimate_cost(args.model, usage)
            spend += cost or 0.0
            print(f"wrote {path} ({len(text)} chars"
                  + (f", ~${cost:.3f}" if cost is not None else "") + ")",
                  file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 — one bad day must not stop the rest
            error = f"{day['date']}: {exc}"
            print(f"annotate: {error}", file=sys.stderr)

    conn.close()
    if written:
        print(f"annotated {len(written)} day(s), ~${spend:.2f} this run "
              f"(estimate; see the console for the real figure)", file=sys.stderr)
    _write_status(args.notes, args.model, written, error, over_cap, args.all_days, spend)
    return 1 if error else 0


def _write_status(notes: Path, model: str, written: list[str],
                  error: str | None, over_cap: int, all_days: bool = False,
                  spend: float = 0.0) -> None:
    notes.mkdir(parents=True, exist_ok=True)
    (notes / STATUS_FILE).write_text(json.dumps({
        "last_run": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "ok": error is None,
        "model": model,
        "written": written,
        "deferred_by_cap": over_cap,
        "estimated_usd": round(spend, 4),
        # What this annotator believes it is covering. `annotator_health` reads
        # it to know which days count as un-interpreted: under --all-days a
        # green day with no note is a gap, and without this the health line
        # would keep reporting "0 missing" while most of the calendar went
        # unwritten. The COUNT stays computed from the data either way — only
        # the scope comes from here, and an unreadable file falls back to the
        # narrower claim.
        "coverage": "all" if all_days else "non-green",
        "error": error,
    }, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
