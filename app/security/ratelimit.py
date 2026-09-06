"""
In-process token-bucket limiter.

Deliberately simple and dependency-free: one process, one bucket per identity.
Behind multiple workers, point `RateLimiter` at Redis instead — the interface
is one method, so the swap is contained.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass
class RateLimiter:
    capacity: int
    window_seconds: int
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def _rate(self) -> float:
        return self.capacity / max(self.window_seconds, 1)

    def check(self, identity: str, cost: float = 1.0) -> tuple[bool, float]:
        """Returns (allowed, seconds_until_next_token)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(identity)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.capacity), updated=now)
                self._buckets[identity] = bucket

            bucket.tokens = min(
                float(self.capacity), bucket.tokens + (now - bucket.updated) * self._rate
            )
            bucket.updated = now

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            deficit = cost - bucket.tokens
            return False, deficit / self._rate

    def reset(self, identity: str | None = None) -> None:
        with self._lock:
            if identity is None:
                self._buckets.clear()
            else:
                self._buckets.pop(identity, None)

    def sweep(self, max_idle_seconds: float = 3600) -> int:
        """Drop buckets nobody has touched, so memory cannot grow unbounded."""
        cutoff = time.monotonic() - max_idle_seconds
        with self._lock:
            stale = [k for k, b in self._buckets.items() if b.updated < cutoff]
            for k in stale:
                del self._buckets[k]
        return len(stale)
