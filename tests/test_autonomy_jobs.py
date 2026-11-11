"""Unattended jobs: the decisions they make must be right without a human."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest

import tools.notify as notify
import tools.promote_pcaps as pp
import tools.scanner_refresh as sr

N = ipaddress.ip_network


def _rdap(table):
    def look(ip):
        for net, org in table.items():
            if ipaddress.ip_address(ip) in N(net):
                return org, [N(net)]
        return "", []
    return look


# --- scanner_refresh.plan ----------------------------------------------------

def test_self_identified_shadowserver_range_is_added_by_its_rdap_cidr():
    """The 2026-11 miss: probes from a Shadowserver /24 nobody had listed."""
    adds, rej, _ = sr.plan(
        current=[N("216.218.206.0/24")], upstream={},
        observed={"199.165.159.77": "unsolicited oversized QR=1 from port 53",
                  "199.165.159.124": "queried shadowserver zone dnsscan.shadowserver.org."},
        rdap=_rdap({"199.165.159.0/24": "The Shadowserver Foundation, Inc."}),
        our_nets=[])
    assert [str(a.net) for a in adds] == ["199.165.159.0/24"] and not rej
    assert adds[0].org == "Shadowserver"


def test_research_scanner_on_a_generic_cloud_is_never_added():
    """REFUSING a Linode or DigitalOcean block is not the job's call."""
    adds, _, notes = sr.plan(
        current=[], upstream={},
        observed={"139.162.66.65": "queried asert-netscout zone"},
        rdap=_rdap({"139.162.0.0/16": "linode-mnt"}), our_nets=[])
    assert adds == []
    assert any("not on the research allowlist" in n for n in notes)


def test_prefix_guard_rejects_wide_ranges():
    adds, rej, _ = sr.plan(current=[], upstream={"Driftnet": [N("2a06:4880::/29")]},
                           observed={}, rdap=_rdap({}), our_nets=[])
    assert adds == [] and rej and "wider than /32" in rej[0]


def test_covered_and_subsumed_entries_collapse():
    adds, _, _ = sr.plan(
        current=[N("162.142.125.0/24")],
        upstream={"Censys": [N("162.142.125.0/25"), N("66.132.195.0/25"),
                             N("66.132.195.0/24")]},
        observed={}, rdap=_rdap({}), our_nets=[])
    assert [str(a.net) for a in adds] == ["66.132.195.0/24"]


def test_our_own_hosts_are_never_candidates():
    adds, _, notes = sr.plan(
        current=[], upstream={}, observed={"203.0.113.9": "research user-agent"},
        rdap=_rdap({"203.0.113.0/24": "Censys, Inc."}), our_nets=[N("203.0.113.9/32")])
    assert adds == [] and notes == []


def test_render_then_validate_round_trips_through_the_honeypot_parser(tmp_path):
    from squatter.source_exemptions import SourceExemptionList
    old = "# header\n10.0.0.0/24\n"
    adds = [sr.Addition(N("199.165.159.0/24"), "Shadowserver", "probe # with hash")]
    new = sr.render(old, adds, "2026-11-11")
    assert sr.validate(new, old, 1) == 2
    f = tmp_path / "x.txt"
    f.write_text(new)
    lst = SourceExemptionList(f)
    assert lst.is_exempt("199.165.159.77") and len(lst) == 2
    # second run appends under the same header, not a new one
    again = sr.render(new, [sr.Addition(N("146.88.240.0/20"), "NetScout ASERT", "x")],
                      "2026-11-18")
    assert again.count(sr.AUTO_HEADER) == 1


def test_validate_refuses_a_file_the_honeypot_would_ignore():
    with pytest.raises(ValueError):
        sr.parse_list("10.0.0.0/24\nnot-a-cidr\n")


def test_upstream_page_that_parses_to_nothing_is_a_warning():
    found, warnings = sr.fetch_upstream(fetch=lambda url, *a: "<html>moved</html>")
    assert "Censys" not in found and any("zero ranges" in w for w in warnings)


# --- promote_pcaps.select_files ----------------------------------------------

def _t(s):
    return datetime.strptime(s, "%Y%m%d%H%M").replace(tzinfo=UTC).timestamp()


def test_pcap_selection_follows_tcpdump_start_minute_and_skips_the_live_file():
    names = ["honeycow-20261029-0032.pcap", "honeycow-20261029-0132.pcap",
             "honeycow-20261029-0232.pcap"]
    events = [(_t("202610290157"), "burst A"),   # inside the 01:32 file
              (_t("202610290100"), "burst B"),   # still the 00:32 file
              (_t("202610290240"), "live")]      # newest file: still being written
    picks = pp.select_files(events, names, kept=set())
    assert picks == {"honeycow-20261029-0132.pcap": "burst A",
                     "honeycow-20261029-0032.pcap": "burst B"}


def test_already_kept_files_are_not_recopied():
    names = ["honeycow-20261029-0032.pcap", "honeycow-20261029-0132.pcap"]
    picks = pp.select_files([(_t("202610290040"), "x")], names,
                            kept={"honeycow-20261029-0032.pcap"})
    assert picks == {}


def test_gzipped_keeps_count_as_kept():
    assert pp.kept_names(["honeycow-20261029-0032.pcap.gz",
                          "honeycow-20261029-0132.pcap",
                          "honeycow-20261029-0232.pcap.gz.part",
                          "php2shell-2026-10"]) == {
        "honeycow-20261029-0032.pcap", "honeycow-20261029-0132.pcap"}


def test_odd_pcap_names_never_reach_the_remote_shell():
    with pytest.raises(ValueError):
        pp.promote("nohost", ["honeycow-20261029-0032.pcap; rm -rf /"])


# --- notify ------------------------------------------------------------------

def test_stale_and_failed_jobs_are_problems():
    now = datetime(2026, 11, 20, tzinfo=UTC)
    probs = notify.health_problems(now, {
        "scanner_refresh": {"last_run": (now - timedelta(days=9)).isoformat(), "ok": True},
        "pcap_promote": {"last_run": now.isoformat(), "ok": False, "error": "ssh down"},
        "ruminate": None,
    }, annot={"ok": True, "missing": []})
    assert any("scanner_refresh: last ran" in p for p in probs)
    assert any("ssh down" in p for p in probs)
    assert any("ruminate: has never reported" in p for p in probs)


def test_healthy_jobs_are_silent():
    now = datetime(2026, 11, 20, tzinfo=UTC)
    fresh = {"last_run": now.isoformat(), "ok": True}
    assert notify.health_problems(
        now, {"scanner_refresh": fresh, "pcap_promote": fresh, "ruminate": fresh},
        annot={"ok": True, "missing": []}) == []


def test_ruminate_status_reads_the_last_summary(tmp_path):
    log = tmp_path / "r.log"
    log.write_text("noise\n2026-11-09T14:03:30+00:00 weekly-scan: done — promoted=0 "
                   "already=0 failed=0 taxonomy=86 triage_remaining=0\n")
    st = notify.ruminate_status(log)
    assert st["ok"] and st["taxonomy"] == 86


def test_day_message_skips_a_stale_note():
    d = {"date": "2026-11-10", "status": "yellow", "why": ["a reason"],
         "narrative": {"text": "**Red today**", "stale": True}}
    _, body = notify.day_message(d, None)
    assert "Note" not in body and "a reason" in body


def test_prod_verification_reads_both_startup_and_sighup_reload_lines():
    start = '{"msg":\'source exemptions: 169 entries from /etc/honeycow/x\'}'
    hup = '{"msg":\'source exemption list reloaded: 169 -> 172\'}'
    assert sr.loaded_count(start) == 169
    assert sr.loaded_count(start + "\n" + hup) == 172  # most recent wins
    assert sr.loaded_count("nothing") is None
