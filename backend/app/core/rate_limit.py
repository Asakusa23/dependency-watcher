from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float


class TokenBucketLimiter:
    """Thread-safe in-memory token bucket rate limiter keyed by client and scope."""

    def __init__(self, capacity: int, refill_per_second: float) -> None:
        self.capacity = max(1, capacity)
        self.refill = max(0.01, refill_per_second)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.capacity), updated=now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.updated)
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill)
            bucket.updated = now
            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0
            retry_after = (cost - bucket.tokens) / self.refill
            return False, max(1.0, retry_after)

    def cleanup(self, older_than_seconds: float = 3600) -> None:
        cutoff = time.monotonic() - older_than_seconds
        with self._lock:
            stale = [key for key, bucket in self._buckets.items() if bucket.updated < cutoff]
            for key in stale:
                self._buckets.pop(key, None)
