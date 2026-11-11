"""Shared plumbing for the unattended analysis-host jobs.

Every scheduled job here follows the same contract, because the operator may
not look for weeks:

  * it records what it did in `<analysis>/state/<job>.json` — when it ran,
    whether it worked, and what it changed — so health can be computed from
    data rather than remembered;
  * anything that needs a human is PUSHED (ntfy via herdmail), never left in a
    queue waiting to be noticed.

`tools/notify.py` reads those status files back; a job that silently stops
running goes stale there and gets reported.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = REPO_ROOT / ".env.analysis"

# ntfy titles/bodies are short plain text; cap them so a runaway `why` list or
# an error traceback can't produce a multi-KB push.
_TITLE_MAX = 120
_BODY_MAX = 3500


def analysis_dir() -> Path:
    return Path(os.environ.get("HONEYCOW_ANALYSIS_DIR",
                               Path.home() / "honeycow-analysis")).expanduser()


def state_dir() -> Path:
    d = analysis_dir() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def setting(name: str) -> str | None:
    """Env var first, then the gitignored `.env.analysis` (same rule as the
    annotator: operator values never live in committed files)."""
    if val := os.environ.get(name):
        return val
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text(errors="replace").splitlines():
            k, _, v = line.partition("=")
            if k.strip() == name:
                return v.strip().strip("\"'") or None
    return None


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def write_status(job: str, status: dict) -> Path:
    """Atomically record a job's last run. `ok` and `last_run` are required
    so a health check never has to guess."""
    if not job.replace("_", "").replace("-", "").isalnum():
        raise ValueError(f"bad job name {job!r}")
    status = {"last_run": now_iso(), **status}
    if "ok" not in status:
        raise ValueError("status must carry 'ok'")
    path = state_dir() / f"{job}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)
    return path


def read_status(job: str) -> dict | None:
    path = state_dir() / f"{job}.json"
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _herdmail() -> str | None:
    if cmd := setting("HONEYCOW_HERDMAIL"):
        return cmd
    default = Path.home() / "projects/herdmail/.venv/bin/herdmail"
    return str(default) if default.is_file() else None


def push(title: str, body: str, *, dry_run: bool = False) -> bool:
    """Send one ntfy notification. Returns True if it was (or would be) sent.

    Never raises: a failed push must not take down the job that wanted to
    report something. It prints to stderr instead, which lands in the journal.
    """
    title = " ".join(title.split())[:_TITLE_MAX]
    body = body[:_BODY_MAX]
    if dry_run:
        print(f"[dry-run] push: {title}\n{body}\n")
        return True
    cmd = _herdmail()
    if not cmd:
        print("[ops] no herdmail found; set HONEYCOW_HERDMAIL", file=sys.stderr)
        return False
    try:
        subprocess.run([cmd, "push", title, body], check=True, timeout=60,
                       capture_output=True, text=True)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[ops] push failed: {exc}", file=sys.stderr)
        return False
