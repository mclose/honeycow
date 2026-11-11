#!/usr/bin/env python3
"""Keep `config/source_exemptions.txt` current, unattended.

    venv/bin/python -m tools.scanner_refresh --dry-run    # plan only
    venv/bin/python -m tools.scanner_refresh --no-deploy  # PR + merge, no prod push
    venv/bin/python -m tools.scanner_refresh              # the weekly timer

WHY THIS EXISTS. The research-scanner list drifts. Shadowserver registered
199.165.159.0/24 on 2026-07-02; it was not on the MISP list we seed from, so
for four months the honeypot answered its `version.bind` probes (the "open
resolver" answer that feeds hosting-provider abuse reports) and the dashboard
painted three days red on its routine 957-byte QR=1 probe.

Two inputs, both reduced to ADDITIONS ONLY:

  1. Upstream publications (MISP Shadowserver warninglist, Censys, Driftnet).
  2. Self-identification in our own data, which is what would have caught the
     case above: sources that query a research zone (`dnsscan.shadowserver.org`
     and friends), send the oversized QR=1 probe from port 53, or announce a
     research user-agent — but are not covered. Each is attributed by RDAP and
     added ONLY if the registered org is on the research allowlist below. A
     scanner on a generic cloud (ASERT on Linode) is therefore never added:
     REFUSING a Linode block would be wrong, and the job does not get to decide
     that.

Guards, any of which stops the run and pushes a notice instead of shipping:
more than MAX_ADDITIONS entries, or any prefix wider than /16 (v4) or /32 (v6).
Worst case of a wrong addition is that we REFUSE a range — its queries are
still logged.

Shipping goes through the normal gate, never around it: branch, PR, the
required `check` CI, merge, then push `origin/main` to the prod remote (whose
post-receive rebuilds the stack). All git work happens in a private worktree
under `<analysis>/state/` so the operator's checkout — which the 4-hourly
timer runs from — is never switched or dirtied.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from tools import ops
    from tools.honeycow_digest import (
        classify_research_scanner,
        is_private_or_loopback,
        load_our_ips,
    )
except ImportError:  # pragma: no cover - run as a script from tools/
    import ops  # type: ignore[no-redef]
    from honeycow_digest import (  # type: ignore[no-redef]
        classify_research_scanner,
        is_private_or_loopback,
        load_our_ips,
    )

EXEMPTIONS_REL = Path("config/source_exemptions.txt")
JOB = "scanner_refresh"
MAX_ADDITIONS = 20
MIN_PREFIX = {4: 16, 6: 32}
OBSERVED_DAYS = 30
CI_TIMEOUT_S = 1500
AUTO_HEADER = "# --- Auto-added by tools/scanner_refresh.py "

# RDAP registrant org -> label. Only orgs whose ranges this file already
# exempts by policy. Matched case-insensitively against the org name.
RESEARCH_ORGS: dict[str, re.Pattern[str]] = {
    "Shadowserver": re.compile(r"shadowserver", re.I),
    "Censys": re.compile(r"\bcensys\b", re.I),
    "Driftnet": re.compile(r"driftnet|internet[- ]measurement", re.I),
    # ASERT's own allocation (146.88.240.0/20 registers to Arbor Networks);
    # its Linode-hosted probes stay out because Linode is not on this list.
    "NetScout ASERT": re.compile(r"arbor networks|netscout", re.I),
}

# Upstream publications. `kind` picks the parser.
UPSTREAM = [
    ("Shadowserver", "json-misp",
     "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/"
     "shadowserver-nt-scanning/list.json"),
    ("Censys", "html", "https://docs.censys.com/docs/opt-out-of-data-collection"),
    ("Driftnet", "html", "https://internet-measurement.com/"),
]

# Research user-agents seen on the HTTP closer. Self-identifying by design.
RESEARCH_UA = re.compile(r"CensysInspect|internet-measurement\.com|shadowserver", re.I)

_CIDR_RX = re.compile(
    r"(?<![0-9a-fA-F:.])(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}"
    r"|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}/[0-9]{1,3})(?![0-9])"
)
_UA = "honeycow-scanner-refresh/1"


@dataclass(frozen=True)
class Addition:
    net: ipaddress.IPv4Network | ipaddress.IPv6Network
    org: str
    evidence: str

    def line(self, day: str) -> str:
        return f"{self.net}  # {self.org}: {self.evidence} ({day})"


# --------------------------------------------------------------------------
# inputs
# --------------------------------------------------------------------------

def parse_list(text: str) -> list:
    """Same rules as `squatter.source_exemptions` — '#' comments, blank lines."""
    nets = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def covered(net, current: list) -> bool:
    return any(net.version == c.version and net.subnet_of(c) for c in current)


def _get(url: str, timeout: int = 30) -> str:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return resp.read(5_000_000).decode("utf-8", errors="replace")


def parse_upstream(kind: str, text: str) -> list:
    if kind == "json-misp":
        raw = json.loads(text).get("list", [])
    else:
        raw = _CIDR_RX.findall(text)
    out = set()
    for entry in raw:
        try:
            out.add(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue
    return sorted(out, key=lambda n: (n.version, n))


def fetch_upstream(fetch=_get) -> tuple[dict[str, list], list[str]]:
    found: dict[str, list] = {}
    warnings: list[str] = []
    for org, kind, url in UPSTREAM:
        try:
            nets = parse_upstream(kind, fetch(url))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            warnings.append(f"{org} upstream fetch failed: {exc}")
            continue
        if not nets:
            # A page that parses to nothing has changed shape; that is a
            # warning, not "they have no scanners any more".
            warnings.append(f"{org} upstream parsed to zero ranges — page changed?")
            continue
        found[org] = nets
    return found, warnings


def observed_sources(db: Path, days: int = OBSERVED_DAYS) -> dict[str, str]:
    """IP -> evidence, for sources that identified themselves as research."""
    since = (datetime.now(UTC) - timedelta(days=days)).timestamp()
    out: dict[str, str] = {}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        for ip, qname in conn.execute(
            "SELECT DISTINCT src_ip, qname FROM dns WHERE ts_epoch >= ? AND "
            "event='query' AND qname IS NOT NULL AND src_ip IS NOT NULL", (since,)
        ):
            if label := classify_research_scanner(qname):
                out.setdefault(ip, f"queried {label} zone {qname}")
        for (ip,) in conn.execute(
            "SELECT DISTINCT src_ip FROM dns WHERE ts_epoch >= ? AND "
            "drop_reason='oversized_datagram' AND src_port=53 AND src_ip IS NOT NULL",
            (since,),
        ):
            out.setdefault(ip, "unsolicited oversized QR=1 from port 53")
        for ip, ua in conn.execute(
            "SELECT DISTINCT client_ip, user_agent FROM http WHERE ts_epoch >= ? "
            "AND client_ip IS NOT NULL AND user_agent IS NOT NULL", (since,)
        ):
            if RESEARCH_UA.search(ua or ""):
                out.setdefault(ip, f"research user-agent {ua[:60]!r}")
    finally:
        conn.close()
    return out


def rdap_lookup(base: str, ip: str, fetch=_get) -> tuple[str, list]:
    """(org name, [registered CIDRs]) from the RDAP proxy's envelope."""
    ipaddress.ip_address(ip)  # validates before it goes anywhere near a URL
    doc = json.loads(fetch(f"{base.rstrip('/')}/ip/{ip}", 20))
    if not doc.get("ok"):
        raise ValueError(f"RDAP not ok for {ip}: {doc.get('meta', {}).get('error_type')}")
    res = doc.get("result") or {}
    org = (res.get("org") or {}).get("name") or ""
    cidrs = [ipaddress.ip_network(c, strict=False) for c in res.get("cidrs") or []]
    return org, cidrs


# --------------------------------------------------------------------------
# planning
# --------------------------------------------------------------------------

def plan(current: list, upstream: dict[str, list], observed: dict[str, str],
         rdap, our_nets: list) -> tuple[list[Addition], list[str], list[str]]:
    """Returns (additions, rejections, notes). Pure apart from `rdap`."""
    adds: list[Addition] = []
    rejected: list[str] = []
    notes: list[str] = []

    def consider(net, org, evidence):
        if covered(net, current) or any(covered(net, [a.net]) for a in adds):
            return
        if net.prefixlen < MIN_PREFIX[net.version]:
            rejected.append(f"{net} ({org}) wider than /{MIN_PREFIX[net.version]}")
            return
        # drop any earlier, narrower addition this one swallows
        adds[:] = [a for a in adds if not (a.net.version == net.version
                                           and a.net.subnet_of(net))]
        adds.append(Addition(net, org, evidence))

    for org, nets in upstream.items():
        for net in nets:
            consider(net, org, "upstream publication")

    looked_up: list = []  # CIDRs RDAP already answered for, to skip neighbours
    for ip in sorted(observed, key=lambda s: (ipaddress.ip_address(s).version,
                                             ipaddress.ip_address(s))):
        addr = ipaddress.ip_address(ip)
        if is_private_or_loopback(ip) or any(addr in n for n in our_nets):
            continue
        if any(addr in n for n in current) or any(addr in a.net for a in adds):
            continue
        if any(addr in n for n in looked_up):
            continue
        try:
            org_name, cidrs = rdap(ip)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            notes.append(f"RDAP failed for {ip}: {exc}")
            continue
        looked_up.extend(cidrs)
        label = next((lbl for lbl, rx in RESEARCH_ORGS.items() if rx.search(org_name)),
                     None)
        if not label:
            notes.append(f"{ip} self-identified ({observed[ip]}) but RDAP org "
                         f"{org_name or '?'!r} is not on the research allowlist — not added")
            continue
        for net in [c for c in cidrs if addr in c] or [ipaddress.ip_network(ip)]:
            consider(net, label, f"{observed[ip]}; RDAP org {org_name!r}")
    return adds, rejected, notes


def render(text: str, adds: list[Addition], day: str) -> str:
    """Append additions under the auto section (created on first use)."""
    if not adds:
        return text
    body = text.rstrip("\n") + "\n"
    if AUTO_HEADER not in text:
        body += ("\n\n" + AUTO_HEADER + "-" * 6 + "\n"
                 "# Additions only, each line naming its org and evidence. Moving an\n"
                 "# entry into its org's block above is fine; the job only checks\n"
                 "# coverage. Remove a wrong one by hand (PR) — the job never deletes.\n")
    body += "".join(a.line(day) + "\n" for a in adds)
    return body


def validate(new_text: str, old_text: str, n_adds: int) -> int:
    """Parse exactly as the honeypot will. A file the loader rejects would be
    silently ignored in prod (it keeps the old list), so never ship one."""
    new = parse_list(new_text)
    old = parse_list(old_text)
    if len(new) != len(old) + n_adds:
        raise ValueError(f"entry count {len(new)} != {len(old)} + {n_adds}")
    return len(new)


# --------------------------------------------------------------------------
# shipping
# --------------------------------------------------------------------------

def run(cmd: list[str], cwd: Path, timeout: int = 300, stdin: str | None = None) -> str:
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       input=stdin)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}… failed ({r.returncode}): "
                           f"{(r.stderr or r.stdout).strip()[-400:]}")
    return r.stdout.strip()


def worktree(repo: Path) -> Path:
    wt = ops.state_dir() / "scanner-refresh-wt"
    run(["git", "fetch", "-q", "origin", "main"], repo)
    if not (wt / ".git").exists():
        run(["git", "worktree", "prune"], repo)
        run(["git", "worktree", "add", "-q", "--detach", str(wt), "origin/main"], repo)
    else:  # ours alone — safe to reset hard
        run(["git", "checkout", "-q", "--detach", "origin/main"], wt)
        run(["git", "reset", "-q", "--hard", "origin/main"], wt)
        run(["git", "clean", "-qfd"], wt)
    return wt


def ship(repo: Path, wt: Path, new_text: str, adds: list[Addition], day: str,
         deploy: bool, vps: str, expected: int) -> dict:
    branch = f"auto/scanner-ranges-{day}"
    (wt / EXEMPTIONS_REL).write_text(new_text)
    run(["git", "checkout", "-q", "-B", branch], wt)
    run(["git", "add", str(EXEMPTIONS_REL)], wt)
    listing = "\n".join(f"- {a.net} — {a.org}: {a.evidence}" for a in adds)
    msg = (f"source_exemptions: add {len(adds)} research scanner range(s)\n\n"
           f"Automated by tools/scanner_refresh.py.\n\n{listing}\n\nmoo! 🐄\n")
    run(["git", "commit", "-q", "-F", "-"], wt, stdin=msg)
    run(["git", "push", "-q", "-f", "-u", "origin", branch], wt)
    url = run(["gh", "pr", "create", "--base", "main", "--head", branch,
               "--title", f"source_exemptions: add {len(adds)} research scanner range(s)",
               "--body", f"Automated weekly refresh (`tools/scanner_refresh.py`).\n\n"
                         f"{listing}\n\nAdditions only. Merged by the job once the "
                         f"required `check` passes; then deployed."], wt)
    pr = url.rsplit("/", 1)[-1]
    out = {"pr": url}
    time.sleep(20)  # let the required check register before watching it
    run(["gh", "pr", "checks", pr, "--watch", "--required", "--interval", "30"], wt,
        timeout=CI_TIMEOUT_S)
    run(["gh", "pr", "merge", pr, "--merge"], wt)
    out["merged"] = True
    # Tidy the branch without gh's --delete-branch, which tries to switch the
    # PRIMARY checkout to main and fails inside a worktree.
    run(["git", "checkout", "-q", "--detach"], wt)
    run(["git", "branch", "-q", "-D", branch], wt)
    subprocess.run(["git", "push", "-q", "origin", "--delete", branch], cwd=wt,
                   capture_output=True, timeout=120)
    if not deploy:
        return out
    run(["git", "fetch", "-q", "origin", "main"], repo)
    run(["git", "push", "-q", "prod", "origin/main:main"], repo, timeout=900)
    out["deployed"] = True
    out["prod_entries"] = verify_prod(vps, expected)
    out["local_checkout"] = fast_forward_local(repo)
    return out


def verify_prod(vps: str, expected: int) -> int:
    """Exercise, don't read back: the running process logs what it loaded."""
    for _ in range(12):
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", vps,
             "docker logs --since 20m honeycow 2>&1 | grep 'source exemptions:' | tail -1"],
            capture_output=True, text=True, timeout=60)
        m = re.search(r"source exemptions: (\d+) entries", r.stdout)
        if m and int(m.group(1)) == expected:
            return expected
        time.sleep(15)
    raise RuntimeError(f"prod did not report {expected} source exemptions after deploy")


def fast_forward_local(repo: Path) -> str:
    """The grader reads the list from the operator's checkout. Bring it along
    only when that is free of risk: on main and clean."""
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo)
    dirty = run(["git", "status", "--porcelain"], repo)
    if branch != "main" or dirty:
        return f"left alone (on {branch}{', dirty' if dirty else ''})"
    run(["git", "merge", "-q", "--ff-only", "origin/main"], repo)
    return "fast-forwarded"


# --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="plan and print; change nothing")
    ap.add_argument("--no-deploy", action="store_true", help="merge but do not push prod")
    ap.add_argument("--db", type=Path, default=ops.analysis_dir() / "honeycow.db")
    ap.add_argument("--vps", default=ops.setting("VPS_HOST") or "honeycow")
    args = ap.parse_args(argv)
    repo = ops.REPO_ROOT
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    status: dict = {"ok": False, "added": [], "rejected": [], "warnings": []}
    try:
        wt = repo if args.dry_run else worktree(repo)
        old_text = (wt / EXEMPTIONS_REL).read_text()
        current = parse_list(old_text)
        upstream, warnings = fetch_upstream()
        status["warnings"] += warnings
        rdap_base = ops.setting("HONEYCOW_RDAP_URL")
        observed = observed_sources(args.db) if args.db.is_file() else {}
        if not args.db.is_file():
            status["warnings"].append(f"no index at {args.db}; observed check skipped")
        if observed and not rdap_base:
            status["warnings"].append("HONEYCOW_RDAP_URL unset; observed check skipped")
            observed = {}
        our_nets = load_our_ips(repo / "tools/our-ips.txt", [])
        adds, rejected, notes = plan(current, upstream, observed,
                                     lambda ip: rdap_lookup(rdap_base, ip), our_nets)
        status.update(rejected=rejected, notes=notes,
                      added=[a.line(day) for a in adds],
                      observed_candidates=len(observed))
        guard = None
        if rejected:
            guard = f"{len(rejected)} range(s) failed the prefix guard"
        elif len(adds) > MAX_ADDITIONS:
            guard = f"{len(adds)} additions exceeds the cap of {MAX_ADDITIONS}"
        for line in status["added"] + [f"REJECTED {r}" for r in rejected] + notes \
                + [f"WARN {w}" for w in status["warnings"]]:
            print(line)
        if args.dry_run:
            print(f"[dry-run] {len(adds)} addition(s); guard: {guard or 'pass'}")
            return 0
        if guard:
            status.update(ok=True, held=guard)
            ops.push("HoneyCow: scanner-range refresh held",
                     f"{guard}. Nothing shipped.\n\n" + "\n".join(
                         status["added"] + [f"REJECTED {r}" for r in rejected]))
            return 0
        if not adds:
            status["ok"] = True
            return 0
        new_text = render(old_text, adds, day)
        expected = validate(new_text, old_text, len(adds))
        status.update(ship(repo, wt, new_text, adds, day, not args.no_deploy,
                           args.vps, expected))
        status["ok"] = True
        ops.push(f"HoneyCow: {len(adds)} scanner range(s) added"
                 + (" + deployed" if status.get("deployed") else ""),
                 "\n".join(status["added"]) + f"\n\n{status.get('pr', '')}\n"
                 f"local checkout: {status.get('local_checkout', 'n/a')}")
        return 0
    except Exception as exc:  # noqa: BLE001 — record + push, never die silently
        status["error"] = f"{type(exc).__name__}: {exc}"
        print(status["error"], file=sys.stderr)
        if not args.dry_run:
            ops.push("HoneyCow: scanner-range refresh FAILED", status["error"])
        return 1
    finally:
        if not args.dry_run:
            ops.write_status(JOB, status)


if __name__ == "__main__":
    sys.exit(main())
