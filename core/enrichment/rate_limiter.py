"""
core/enrichment/rate_limiter.py
Per-provider token-bucket rate limiter.

Each provider gets its own :class:`RateLimiter` instance with a configured
request quota (``max_tokens``) and refill rate (``refill_seconds``).

The limiter is **thread-safe** — the :class:`EnrichWorker` QThread can
safely call :meth:`acquire` while the UI thread reads cached results.
"""
from __future__ import annotations

import threading
import time


class RateLimiter:
    """Simple token-bucket rate limiter.

    Parameters
    ----------
    max_tokens : int
        Maximum burst size (bucket capacity).
    refill_seconds : float
        Time in seconds for the full bucket to refill from zero.
        Tokens are added continuously at ``max_tokens / refill_seconds``
        per second.
    """

    def __init__(self, max_tokens: int, refill_seconds: float) -> None:
        self._max_tokens = max_tokens
        self._refill_rate = max_tokens / refill_seconds  # tokens per second
        self._tokens = float(max_tokens)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since the last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max_tokens, self._tokens + elapsed * self._refill_rate)
        self._last_refill = now

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available or *timeout* seconds elapse.

        Returns ``True`` if a token was acquired, ``False`` on timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            # No token available — wait a short interval and retry
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.1, remaining))

    def try_acquire(self) -> bool:
        """Non-blocking: attempt to consume one token.

        Returns ``True`` if successful, ``False`` if the bucket is empty.
        """
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False
