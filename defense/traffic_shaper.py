import asyncio
from collections import deque
from typing import Any

import structlog

from defense.base import BaseDefender

logger = structlog.get_logger(__name__)


class TrafficShaper(BaseDefender):
    name = "traffic_shaper"
    description = "Traffic analysis and shaping with burst detection"

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._traffic_history: deque[tuple[float, int]] = deque(maxlen=300)
        self._per_ip_stats: dict[str, dict] = {}
        self._stats = {"total_bytes": 0, "peak_rps": 0, "peak_bps": 0}

    async def run(
        self,
        window_size: int = 60,
        burst_threshold: int = 5000,
        **kwargs: Any,
    ) -> None:
        self._window_size = window_size
        self._burst_threshold = burst_threshold
        logger.info("traffic_shaper_started", window=window_size)

        while not self.session.is_stopped:
            await self.session._pause_event.wait()
            self.session.update_stats(
                blocked_count=len(self._per_ip_stats),
                rate_hits=sum(1 for s in self._per_ip_stats.values() if s.get("blocked", False)),
            )
            await asyncio.sleep(0.5)

    def record_traffic(self, client_ip: str, bytes_count: int) -> dict[str, Any]:
        now = asyncio.get_event_loop().time()
        self._traffic_history.append((now, bytes_count))
        self._stats["total_bytes"] += bytes_count

        if client_ip not in self._per_ip_stats:
            self._per_ip_stats[client_ip] = {"bytes": 0, "requests": 0, "first_seen": now, "blocked": False}

        stats = self._per_ip_stats[client_ip]
        stats["bytes"] += bytes_count
        stats["requests"] += 1

        cutoff = now - self._window_size
        recent = [(t, b) for t, b in self._traffic_history if t > cutoff]
        recent_bytes = sum(b for _, b in recent)
        recent_rps = len(recent) / self._window_size if self._window_size > 0 else 0

        self._stats["peak_rps"] = max(self._stats["peak_rps"], recent_rps)
        self._stats["peak_bps"] = max(self._stats["peak_bps"], recent_bytes / self._window_size)

        action = "allow"
        if recent_rps > self._burst_threshold:
            action = "throttle"
            stats["blocked"] = True
            logger.warning("burst_detected", ip=client_ip, rps=recent_rps)

        return {
            "action": action,
            "current_rps": recent_rps,
            "ip_requests": stats["requests"],
            "ip_bytes": stats["bytes"],
        }

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_bytes": self._stats["total_bytes"],
            "peak_rps": self._stats["peak_rps"],
            "peak_bps": self._stats["peak_bps"],
            "tracked_ips": len(self._per_ip_stats),
        }
