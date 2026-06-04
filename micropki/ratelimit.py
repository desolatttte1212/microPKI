from __future__ import annotations
import time
from collections import defaultdict
from threading import Lock
from typing import Dict


class TokenBucket:
    """Token bucket rate limiter (thread-safe)."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate  # tokens per second
        self.burst = burst  # max tokens
        self._tokens = float(burst)
        self._last_update = time.monotonic()
        self._lock = Lock()

    def _refill(self):
        now = time.monotonic()
        delta = now - self._last_update
        self._tokens = min(self.burst, self._tokens + delta * self.rate)
        self._last_update = now

    def allow(self, tokens: int = 1) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def retry_after(self, tokens: int = 1) -> float:
        """Returns seconds to wait before next request might succeed."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                return 0.0
            needed = tokens - self._tokens
            return needed / self.rate if self.rate > 0 else float('inf')


class RateLimiter:
    """Per-IP rate limiter using token buckets."""

    def __init__(self, rate: float = 0.0, burst: int = 10):
        self.rate = rate
        self.burst = burst
        self._buckets: Dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate, burst)
        )
        self._lock = Lock()

    def allow(self, client_ip: str, tokens: int = 1) -> tuple[bool, float]:
        """Returns (allowed, retry_after_seconds)."""
        if self.rate <= 0:
            return True, 0.0

        with self._lock:
            bucket = self._buckets[client_ip]

        if bucket.allow(tokens):
            return True, 0.0
        return False, bucket.retry_after(tokens)