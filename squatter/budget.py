"""Outbound byte budget over a rolling time window.

A circuit breaker for total response bytes per unit time. If we ever
emit more than `max_bytes` in any `window_seconds` interval, the
budget refuses further charges until enough old bytes age out.

Used by the DNS and HTTP listeners as a hard cap on amplification
participation: even if every other defense fails (rate limiter
bypass, code bug producing a response loop, attacker-discovered
gadget), the box can't sustain >100 MB/hour of outbound. At our
normal traffic level (~few MB/day), the headroom is ~2000x — false
positives are essentially impossible during legitimate operation.

State is in-memory only; a container restart resets the budget.
That's an acceptable trade-off — the alternative is persisting
state to disk, which adds complexity and a file the read-only image
would have to permit writing.
"""

from __future__ import annotations

import collections
import threading
import time


class OutboundBudget:
    """Token-bucket-ish circuit breaker keyed on a rolling time window."""

    def __init__(
        self,
        max_bytes: int = 100_000_000,
        window_seconds: int = 3600,
        clock=None,
    ) -> None:
        self.max_bytes = max_bytes
        self.window_seconds = window_seconds
        # Per-second bucket deque + running total for O(1) amortized charge.
        # Lock is for thread-safety in the asyncio + signal handler context.
        self._buckets: collections.deque[tuple[int, int]] = collections.deque()
        self._total = 0
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()

    def _now(self) -> int:
        return int(self._clock())

    def _prune(self, now: int) -> None:
        cutoff = now - self.window_seconds
        while self._buckets and self._buckets[0][0] <= cutoff:
            _, sz = self._buckets.popleft()
            self._total -= sz

    def remaining(self) -> int:
        """Bytes remaining in the current window. Never negative."""
        with self._lock:
            self._prune(self._now())
            return max(0, self.max_bytes - self._total)

    def try_charge(self, n: int) -> bool:
        """Attempt to deduct `n` bytes from the budget.

        Returns True if there was room (and the charge was applied),
        False if the charge would have exceeded `max_bytes` (no change).
        """
        if n <= 0:
            return True
        with self._lock:
            now = self._now()
            self._prune(now)
            if self._total + n > self.max_bytes:
                return False
            if self._buckets and self._buckets[-1][0] == now:
                ts, sz = self._buckets.pop()
                self._buckets.append((ts, sz + n))
            else:
                self._buckets.append((now, n))
            self._total += n
            return True

    def force_charge(self, n: int) -> None:
        """Charge `n` bytes unconditionally (used when the caller has
        already decided to emit a byte-count regardless of budget — e.g.
        when sending the budget-exhausted substitute response itself).
        """
        if n <= 0:
            return
        with self._lock:
            now = self._now()
            self._prune(now)
            if self._buckets and self._buckets[-1][0] == now:
                ts, sz = self._buckets.pop()
                self._buckets.append((ts, sz + n))
            else:
                self._buckets.append((now, n))
            self._total += n

    @property
    def total_used(self) -> int:
        with self._lock:
            self._prune(self._now())
            return self._total
