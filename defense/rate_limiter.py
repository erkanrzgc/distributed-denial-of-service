import asyncio
import time
from collections import defaultdict
from typing import Any

import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)


class TokenBucket:
    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class SlidingWindow:
    def __init__(self, max_requests: int, window_secs: float) -> None:
        self.max_requests = max_requests
        self.window_secs = window_secs
        self.windows: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_secs
        self.windows[key] = [t for t in self.windows[key] if t > cutoff]
        if len(self.windows[key]) >= self.max_requests:
            return False
        self.windows[key].append(now)
        return True

    def cleanup(self) -> None:
        now = time.monotonic()
        cutoff = now - self.window_secs * 2
        expired = [k for k, v in self.windows.items() if not any(t > cutoff for t in v)]
        for k in expired:
            del self.windows[k]


class RateLimiter(BaseDefender):
    name = "rate_limiter"
    description = "Token bucket and sliding window rate limiter"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._buckets: dict[str, TokenBucket] = {}
        self._sliding_window = SlidingWindow(max_requests=100, window_secs=60)
        self._blocked: set[str] = set()
        self._stats = {"allowed": 0, "blocked": 0, "rate_hits": 0}

    async def run(
        self,
        max_rate: int = 100,
        window_secs: float = 60,
        block_duration: float = 300,
        **kwargs: Any,
    ) -> None:
        self._sliding_window = SlidingWindow(max_requests=max_rate, window_secs=window_secs)
        self._rate = max_rate
        self._block_duration = block_duration
        logger.info("rate_limiter_started", max_rate=max_rate, window=window_secs)

        while not self.session.is_stopped:
            await self.session._pause_event.wait()
            self._sliding_window.cleanup()
            self.session.update_stats(
                packets_sent=self._stats["allowed"] + self._stats["blocked"],
                blocked_count=self._stats["blocked"],
                passed_count=self._stats["allowed"],
                rate_hits=self._stats["rate_hits"],
            )
            await asyncio.sleep(0.5)

    def check_request(self, client_ip: str) -> dict[str, Any]:
        if client_ip in self._blocked:
            self._stats["blocked"] += 1
            return {"allowed": False, "reason": "blocked"}

        if not self._sliding_window.allow(client_ip):
            self._stats["rate_hits"] += 1
            self._stats["blocked"] += 1
            self._blocked.add(client_ip)
            asyncio.get_event_loop().call_later(self._block_duration, self._unblock, client_ip)
            return {"allowed": False, "reason": "rate_limit"}

        self._stats["allowed"] += 1
        return {"allowed": True, "reason": "ok"}

    def _unblock(self, ip: str) -> None:
        self._blocked.discard(ip)

    def get_stats(self) -> dict[str, Any]:
        return {
            "allowed": self._stats["allowed"],
            "blocked": self._stats["blocked"],
            "rate_hits": self._stats["rate_hits"],
            "active_blocks": len(self._blocked),
            "active_windows": len(self._sliding_window.windows),
        }
