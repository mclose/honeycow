"""Deployment-file shape and parity with chaoscow's conventions."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_required_files_exist():
    for name in [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.prod.yml",
        "Makefile",
        "requirements.txt",
        "requirements.lock",
        ".env.example",
        ".gitignore",
        ".dockerignore",
        "config/exemptions.txt",
        "VERSION",
        "README.md",
        "CLAUDE.md",
        "CHANGELOG.md",
        "static/index.html",
        "tools/healthcheck.py",
        "squatter/__init__.py",
        "squatter/base.py",
        "squatter/dispatch.py",
        "squatter/exemptions.py",
        "honey_ns.py",
        "honey_http.py",
        "honey_logging.py",
    ]:
        assert (ROOT / name).is_file(), f"missing {name}"


def test_env_example_has_required_var():
    text = (ROOT / ".env.example").read_text()
    assert "HONEY_PUBLIC_A=" in text


def test_dockerfile_runs_non_root():
    text = (ROOT / "Dockerfile").read_text()
    assert "USER honey" in text


def test_compose_publishes_dns_and_http_ports():
    text = (ROOT / "docker-compose.yml").read_text()
    assert "53:53/udp" in text
    assert "53:53/tcp" in text
    assert "80:80/tcp" in text


def test_compose_binds_exemptions_dir():
    # The compose file binds the config/ directory (not the single file)
    # so that atomic-rename writes from rsync/editors don't pin to a stale
    # inode. The exemption file lives at /etc/honeycow/exemptions.txt inside
    # the container regardless.
    text = (ROOT / "docker-compose.yml").read_text()
    assert "./config:/etc/honeycow" in text
    assert "HONEY_EXEMPTION_FILE: /etc/honeycow/exemptions.txt" in text


def test_exemptions_file_documented():
    text = (ROOT / "config" / "exemptions.txt").read_text()
    # Has the documentation header explaining format + reload.
    assert "SIGHUP" in text or "kill -HUP" in text or "#" in text


# --- herd cow runtime (step 3) ----------------------------------------------


def _strip_comments(text: str) -> str:
    # Drop `#...` to end of line so assertions test real directives, not the
    # prose that explains what the cow deliberately does NOT do.
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_cow_compose_exists_and_is_build_less():
    text = _strip_comments((ROOT / "docker-compose.cow.yml").read_text())
    # A cow PULLS a pinned image; it must not build (no source on the box).
    assert "build:" not in text
    assert "HONEY_IMAGE" in text
    # honey-ns still publishes DNS; Caddy owns 80/443.
    assert "53:53/udp" in text
    assert "53:53/tcp" in text


def test_cow_compose_requires_site_id():
    # The cow's whole reason for existing is attributable digests, so the
    # vantage-point id must be mandatory (errors if unset), not defaulted.
    text = (ROOT / "docker-compose.cow.yml").read_text()
    assert "HONEY_SITE_ID: ${HONEY_SITE_ID:?" in text


def test_cow_stack_carries_no_dns01_secrets():
    # Cert design is HTTP-01 self-issuance: zero secrets on a throwaway box.
    # No acme.sh sidecar, no TSIG/nsupdate key in the actual cow config
    # (comments that explain the *absence* of these are stripped first).
    compose = _strip_comments((ROOT / "docker-compose.cow.yml").read_text()).lower()
    caddy = _strip_comments((ROOT / "caddy" / "Caddyfile.cow").read_text()).lower()
    for needle in ("acme.sh", "nsupdate", "tsig", "dns-01"):
        assert needle not in compose, f"cow compose leaks {needle}"
        assert needle not in caddy, f"cow Caddyfile leaks {needle}"


def test_cow_caddyfile_http01_and_proxies_closer():
    text = (ROOT / "caddy" / "Caddyfile.cow").read_text()
    assert "{$HERD_FQDN}" in text          # per-cow hostname, env-substituted
    assert "reverse_proxy honey-ns:80" in text
    # No external cert files mounted (that's the flagship DNS-01 model).
    assert "/certs/" not in text


def test_base_compose_passes_site_id():
    # Flagship passthrough so HONEY_SITE_ID actually reaches the container.
    text = (ROOT / "docker-compose.yml").read_text()
    assert "HONEY_SITE_ID: ${HONEY_SITE_ID:-}" in text


# --- nightly analysis pipeline ---------------------------------------------


def test_refresh_script_exists_and_executable():
    p = ROOT / "tools" / "refresh-index.sh"
    assert p.is_file(), "missing tools/refresh-index.sh"
    assert p.stat().st_mode & 0o111, "refresh-index.sh must be executable"
    text = p.read_text()
    # Persistent data dir by design (see docstring) — never /tmp.
    assert "HONEYCOW_ANALYSIS_DIR" in text
    assert "flock" in text          # no overlapping runs
    assert "--dry-run" in text      # mutating tool honours dry-run


def test_systemd_units_are_host_agnostic():
    svc = (ROOT / "deploy" / "systemd" / "honeycow-index.service").read_text()
    tmr = (ROOT / "deploy" / "systemd" / "honeycow-index.timer").read_text()
    # User unit: paths via %h, no hardcoded /home/<someone> or host IPs.
    assert "%h/projects/honeycow/tools/refresh-index.sh" in svc
    assert "/home/" not in svc, "service leaks an absolute home path"
    assert "142.93" not in svc and "142.93" not in tmr, "unit leaks a host IP"
    assert "OnCalendar=" in tmr
    assert "Persistent=true" in tmr
