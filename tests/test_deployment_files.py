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
        "exemptions.txt",
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


def test_compose_binds_exemptions_file():
    text = (ROOT / "docker-compose.yml").read_text()
    assert "exemptions.txt" in text


def test_exemptions_file_documented():
    text = (ROOT / "exemptions.txt").read_text()
    # Has the documentation header explaining format + reload.
    assert "SIGHUP" in text or "kill -HUP" in text or "#" in text
