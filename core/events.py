import asyncio
from collections.abc import Callable
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class EventType(str, Enum):
    SESSION_STARTED = "session_started"
    SESSION_STOPPED = "session_stopped"
    SESSION_PAUSED = "session_paused"
    SESSION_RESUMED = "session_resumed"
    STATS_UPDATED = "stats_updated"
    ATTACK_STARTED = "attack_started"
    ATTACK_PROGRESS = "attack_progress"
    ATTACK_COMPLETED = "attack_completed"
    DEFENSE_ALERT = "defense_alert"
    DEFENSE_BLOCKED = "defense_blocked"
    DETECT_ANOMALY = "detect_anomaly"
    DETECT_ALERT = "detect_alert"
    CONFIG_CHANGED = "config_changed"
    UI_REFRESH = "ui_refresh"
    SHUTDOWN = "shutdown"


EventHandler = Callable[..., Any]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[EventHandler]] = {e: [] for e in EventType}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    async def publish(self, event_type: EventType, **data: Any) -> None:
        await self._queue.put((event_type, data))

    def publish_sync(self, event_type: EventType, **data: Any) -> None:
        for handler in self._subscribers[event_type]:
            try:
                result = handler(**data)
                if asyncio.iscoroutine(result):
                    asyncio.ensure_future(result)
            except Exception as e:
                logger.warning("event_handler_error", event=event_type.value, error=str(e))

    async def _process_events(self) -> None:
        while self._running:
            try:
                event_type, data = await asyncio.wait_for(self._queue.get(), timeout=0.1)
                for handler in self._subscribers[event_type]:
                    try:
                        result = handler(**data)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception as e:
                        logger.warning("event_handler_error", event=event_type.value, error=str(e))
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._process_events())

    async def stop(self) -> None:
        self._running = False
        if hasattr(self, "_task"):
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


event_bus = EventBus()
