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
