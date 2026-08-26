"""Tests for the UDP rate limiter, with focus on the LRU bucket cap.

Spoofed-source floods are honeycow's stated threat model; without the
cap, the bucket dict can grow without bound until the container OOMs.
"""

from __future__ import annotations

from honey_ns import TokenBucketRateLimiter


def test_allow_under_burst_does_not_evict():
    rl = TokenBucketRateLimiter(rate=10.0, burst=5, max_keys=100)
    for i in range(50):
        assert rl.allow(f"10.0.0.{i}", "x") is True
    assert len(rl._buckets) == 50


def test_bucket_dict_is_capped_under_flood():
    rl = TokenBucketRateLimiter(rate=10.0, burst=5, max_keys=10)
    for i in range(1000):
        rl.allow(f"10.0.{i // 256}.{i % 256}", "x")
    assert len(rl._buckets) == 10


def test_lru_evicts_least_recently_used():
    rl = TokenBucketRateLimiter(rate=10.0, burst=5, max_keys=3)
    rl.allow("a", "x")
    rl.allow("b", "x")
    rl.allow("c", "x")
    # Touch 'a' to make it most-recent.
    rl.allow("a", "x")
    # Insert a 4th key — should evict 'b' (least recently used), not 'a'.
    rl.allow("d", "x")
    keys = {k[0] for k in rl._buckets.keys()}
    assert "b" not in keys
    assert keys == {"a", "c", "d"}


def test_disabled_limiter_does_not_track_buckets():
    rl = TokenBucketRateLimiter(rate=10.0, burst=5, enabled=False, max_keys=10)
    for i in range(100):
        assert rl.allow(f"10.0.0.{i}", "x") is True
    assert len(rl._buckets) == 0  # disabled limiter never inserts


def test_burst_then_throttle():
    """Sustained traffic from one source eventually gets rate-limited."""
    rl = TokenBucketRateLimiter(rate=1.0, burst=3, max_keys=10)
    # First 3 allowed (burst); 4th throttled.
    assert rl.allow("10.0.0.1", "x") is True
    assert rl.allow("10.0.0.1", "x") is True
    assert rl.allow("10.0.0.1", "x") is True
    assert rl.allow("10.0.0.1", "x") is False


# --- the shipped sizing ------------------------------------------------------
#
# These pin the *defaults*, not the class: the 200/400 they replaced let the
# 2026-08-03 spoofed burst (831 queries in 3.05s) through completely, so
# honeycow reflected every packet at the victim. If someone loosens the
# defaults again, these fail and say why.

def _replay(monkeypatch, ip, per_sec):
    """Feed `per_sec[i]` queries during second i, at the shipped defaults."""
    import honey_ns as hn

    clock = {"t": 0.0}
    monkeypatch.setattr(hn.time, "monotonic", lambda: clock["t"])
    rl = hn.TokenBucketRateLimiter(hn.DEFAULT_UDP_RATELIMIT_RATE,
                                   hn.DEFAULT_UDP_RATELIMIT_BURST)
    allowed = total = 0
    for sec, n in enumerate(per_sec):
        for i in range(n):
            clock["t"] = sec + i / n
            total += 1
            allowed += rl.allow(ip, "udp")
    return allowed, total


def test_defaults_clip_the_2026_08_03_reflection_burst(monkeypatch):
    # Real per-second distribution of the burst, from the SQLite index.
    allowed, total = _replay(monkeypatch, "163.5.59.20", [99, 270, 302, 160])
    assert total == 831
    assert allowed < total * 0.2, f"expected >80% clipped, answered {allowed}/{total}"


def test_defaults_do_not_touch_the_busiest_legitimate_second(monkeypatch):
    # 53 q/s is the fastest single second ever seen from a non-reflection
    # source (a TXT prober, 2026-08-22). It must pass whole.
    assert _replay(monkeypatch, "209.38.67.124", [53]) == (53, 53)
    assert _replay(monkeypatch, "185.242.3.3", [33]) == (33, 33)
