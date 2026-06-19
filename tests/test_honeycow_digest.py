"""honeycow_digest is the shared parse+classify home for both the central
report and the (forthcoming) cow-side digest emitter.

These tests pin two things PR-A must hold:
  1. The classifier behaves identically whether imported from the shared
     lib or from morning_report (which re-exports it for compatibility).
  2. The lib is self-contained — importable without morning_report.
"""

from __future__ import annotations

import tools.honeycow_digest as digest
import tools.morning_report as report


def test_morning_report_reexports_are_the_same_objects():
    # The report must not carry its own divergent copy of the classifier.
    assert report.classify_query is digest.classify_query
    assert report.classify_research_scanner is digest.classify_research_scanner
    assert report.FLAG_RD is digest.FLAG_RD


def test_classifier_runs_from_the_lib_directly():
    ev = {"qname": "version.bind.", "qclass_name": "CH", "qtype_name": "TXT"}
    assert digest.classify_query(ev) == "chaos-banner"
    assert digest.classify_research_scanner("x.shadowserver.org.") == "shadowserver"
