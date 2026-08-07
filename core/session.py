import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)


class SessionStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SessionStats:
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    success_rate: float = 0.0
    bandwidth_mbps: float = 0.0
    blocked_count: int = 0
    passed_count: int = 0
    rate_hits: int = 0
    challenges_sent: int = 0
    waf_triggers: int = 0
    start_time: float = 0.0

    def reset(self) -> None:
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.errors = 0
        self.success_rate = 0.0
        self.bandwidth_mbps = 0.0
        self.blocked_count = 0
        self.passed_count = 0
        self.rate_hits = 0
        self.challenges_sent = 0
        self.waf_triggers = 0


@dataclass
class Session:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    module: str = ""
    mode: str = "attack"
    target: str = ""
    status: SessionStatus = SessionStatus.IDLE
    stats: SessionStats = field(default_factory=SessionStats)
    config: dict[str, Any] = field(default_factory=dict)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error_message: Optional[str] = None
    _stop_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    _pause_event: asyncio.Event = field(default_factory=lambda: asyncio.Event(), repr=False)
    _on_stats_update: Optional[Callable] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._pause_event.set()

    def start(self) -> None:
        self.status = SessionStatus.RUNNING
        self.start_time = time.monotonic()
        self.stats.start_time = self.start_time
        self.stats.reset()
        self._stop_event.clear()
        self._pause_event.set()
        logger.info("session_started", session_id=self.session_id, module=self.module, target=self.target)

    def stop(self) -> None:
        self.status = SessionStatus.COMPLETED
        self.end_time = time.monotonic()
        self._stop_event.set()
        self._pause_event.set()
        logger.info("session_stopped", session_id=self.session_id, duration=self.duration)

    def pause(self) -> None:
        if self.status == SessionStatus.RUNNING:
            self.status = SessionStatus.PAUSED
            self._pause_event.clear()
            logger.info("session_paused", session_id=self.session_id)

    def resume(self) -> None:
        if self.status == SessionStatus.PAUSED:
            self.status = SessionStatus.RUNNING
            self._pause_event.set()
            logger.info("session_resumed", session_id=self.session_id)

    def fail(self, error: str) -> None:
        self.status = SessionStatus.FAILED
        self.end_time = time.monotonic()
        self.error_message = error
        self._stop_event.set()
        logger.error("session_failed", session_id=self.session_id, error=error)

    @property
    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    @property
    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    @property
    def duration(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.monotonic()
        return end - self.start_time

    def update_stats(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            if hasattr(self.stats, key):
                setattr(self.stats, key, value)
        if self.stats.packets_sent > 0:
            self.stats.success_rate = (
                (self.stats.packets_sent - self.stats.errors) / self.stats.packets_sent * 100
            )
        elapsed = self.duration
        if elapsed > 0:
            self.stats.bandwidth_mbps = (self.stats.bytes_sent * 8) / elapsed / 1_000_000

        if self._on_stats_update:
            try:
                self._on_stats_update(self.stats)
            except Exception:
                pass

    async def wait_for_stop(self) -> None:
        while not self._stop_event.is_set():
            await self._pause_event.wait()
            await asyncio.sleep(0.01)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "module": self.module,
            "mode": self.mode,
            "target": self.target,
            "status": self.status.value,
            "duration": self.duration,
            "packets_sent": self.stats.packets_sent,
            "errors": self.stats.errors,
            "success_rate": self.stats.success_rate,
            "bandwidth_mbps": self.stats.bandwidth_mbps,
            "error_message": self.error_message,
        }


class SessionManager:
    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.current_session: Optional[Session] = None

    def create_session(self, module: str, target: str, mode: str = "attack", **config: Any) -> Session:
        session = Session(module=module, target=target, mode=mode, config=config)
        self.sessions[session.session_id] = session
        self.current_session = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)

    def get_current(self) -> Optional[Session]:
        return self.current_session

    def list_sessions(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self.sessions.values()]

    def stop_all(self) -> None:
        for session in self.sessions.values():
            if session.status == SessionStatus.RUNNING:
                session.stop()

    def cleanup_completed(self) -> int:
        to_remove = [
            sid for sid, s in self.sessions.items()
            if s.status in (SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED)
        ]
        for sid in to_remove:
            del self.sessions[sid]
        return len(to_remove)
