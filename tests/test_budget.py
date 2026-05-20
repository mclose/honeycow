"""Tests for the rolling-window outbound byte budget."""

from __future__ import annotations

from squatter.budget import OutboundBudget


class FakeClock:
    def __init__(self, t: float = 0.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def test_under_budget_charges_succeed():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=1000, window_seconds=60, clock=clk)
    assert b.try_charge(100) is True
    assert b.try_charge(200) is True
    assert b.total_used == 300


def test_over_budget_charge_refused_and_state_unchanged():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=1000, window_seconds=60, clock=clk)
    b.try_charge(900)
    assert b.try_charge(200) is False
    # Refused charge must not have advanced the total.
    assert b.total_used == 900


def test_rolling_window_evicts_old_buckets():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=1000, window_seconds=60, clock=clk)
    b.try_charge(800)
    # 61 seconds later — the original charge has aged out.
    clk.t = 1061.0
    assert b.total_used == 0
    # Full budget should be available again.
    assert b.try_charge(800) is True


def test_remaining_tracks_usage():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=1000, window_seconds=60, clock=clk)
    assert b.remaining() == 1000
    b.try_charge(300)
    assert b.remaining() == 700
    b.try_charge(700)
    assert b.remaining() == 0


def test_partial_window_eviction():
    """Only the *aged-out* portion of the window should free budget."""
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=1000, window_seconds=60, clock=clk)
    b.try_charge(400)
    clk.t = 1030.0
    b.try_charge(400)
    # 31 seconds further on: the first charge is now 61s old (evicted),
    # the second is 31s old (still in window).
    clk.t = 1061.0
    assert b.total_used == 400


def test_force_charge_ignores_cap():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=100, window_seconds=60, clock=clk)
    b.try_charge(80)
    # Even though we'd be over budget, force_charge still applies.
    b.force_charge(50)
    assert b.total_used == 130
    # Future try_charge sees the inflated total.
    assert b.try_charge(1) is False


def test_zero_or_negative_charge_is_noop():
    clk = FakeClock(1000.0)
    b = OutboundBudget(max_bytes=100, window_seconds=60, clock=clk)
    assert b.try_charge(0) is True
    assert b.try_charge(-5) is True
    assert b.total_used == 0
