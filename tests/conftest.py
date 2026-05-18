"""Test-suite import setup.

Identity env vars must be in place BEFORE squatter.base is imported anywhere,
so this conftest sets them via setdefault at module load time. Production
must set HONEY_PUBLIC_A explicitly; tests use TEST-NET-3 / documentation
ranges per RFC 5737 / 3849.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("HONEY_PUBLIC_A", "203.0.113.10")
os.environ.setdefault("HONEY_PUBLIC_AAAA", "2001:db8::10")
os.environ.setdefault("HONEY_DOMAIN", "honeycow.test.")
os.environ.setdefault("HONEY_NS_HOSTS", "ns1.honeycow.test,ns2.honeycow.test")
os.environ.setdefault("HONEY_ABUSE_EMAIL", "abuse@honeycow.test")
os.environ.setdefault(
    "HONEY_TXT_CALLING_CARD",
    "honeycow: this is not the cow you are looking for. a polite ns squatter. "
    "https://honeycow.test abuse@honeycow.test",
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def exemption_file(tmp_path: Path) -> Path:
    p = tmp_path / "exemptions.txt"
    p.write_text("# comment\nexample.com\n\nblocked.org\n")
    return p
