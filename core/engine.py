import asyncio
import importlib
from typing import Any, Optional, Type

import structlog

from core.config import get_config
from core.events import EventBus, EventType, event_bus
from core.session import Session, SessionManager

logger = structlog.get_logger(__name__)

session_manager = SessionManager()


class BaseModule:
    name: str = "base"
    description: str = ""
    mode: str = "attack"

    def __init__(self, session: Session, event_bus: EventBus):
        self.session = session
        self.event_bus = event_bus
        self._task: Optional[asyncio.Task] = None

    async def run(self, **kwargs: Any) -> None:
        raise NotImplementedError

    async def start(self, **kwargs: Any) -> None:
        self.session.start()
        if self.event_bus:
            self.event_bus.publish_sync(EventType.SESSION_STARTED, session=self.session)
        try:
            self._task = asyncio.create_task(self.run(**kwargs))
            await self._task
        except asyncio.CancelledError:
            logger.info("module_cancelled", module=self.name)
        except Exception as e:
            self.session.fail(str(e))
            logger.error("module_error", module=self.name, error=str(e))
        finally:
            if self.session.status.value not in ("completed", "failed", "cancelled"):
                self.session.stop()
            if self.event_bus:
                self.event_bus.publish_sync(EventType.SESSION_STOPPED, session=self.session)

    def stop(self) -> None:
        self.session.stop()
        if self._task and not self._task.done():
            self._task.cancel()

    def pause(self) -> None:
        self.session.pause()

    def resume(self) -> None:
        self.session.resume()

    @classmethod
    def get_config_schema(cls) -> dict[str, Any]:
        return {}


class ModuleRegistry:
    def __init__(self) -> None:
        self._attack_modules: dict[str, Type[BaseModule]] = {}
        self._defense_modules: dict[str, Type[BaseModule]] = {}
        self._detection_modules: dict[str, Type[BaseModule]] = {}

    def register_attack(self, module_class: Type[BaseModule]) -> Type[BaseModule]:
        self._attack_modules[module_class.name] = module_class
        return module_class

    def register_defense(self, module_class: Type[BaseModule]) -> Type[BaseModule]:
        self._defense_modules[module_class.name] = module_class
        return module_class

    def register_detection(self, module_class: Type[BaseModule]) -> Type[BaseModule]:
        self._detection_modules[module_class.name] = module_class
        return module_class

    def list_attacks(self) -> dict[str, Type[BaseModule]]:
        return self._attack_modules

    def list_defenses(self) -> dict[str, Type[BaseModule]]:
        return self._defense_modules

    def list_detections(self) -> dict[str, Type[BaseModule]]:
        return self._detection_modules

    def get_module(self, name: str, mode: str = "attack") -> Optional[Type[BaseModule]]:
        if mode == "attack":
            return self._attack_modules.get(name)
        elif mode == "defense":
            return self._defense_modules.get(name)
        elif mode == "detection":
            return self._detection_modules.get(name)
        return None

    def auto_discover(self) -> None:
        modules_to_load = [
            ("attack", ["syn_flood", "http_flood", "udp_flood", "slowloris", "slow_read", "layer7", "icmp_flood", "amplification"]),
            ("defense", ["rate_limiter", "dynamic_firewall", "challenge", "traffic_shaper", "reverse_proxy", "waf", "data_guard"]),
            ("detection", ["monitor", "anomaly", "fingerprint", "entropy", "alert"]),
        ]
        for package, modules in modules_to_load:
            for mod_name in modules:
                try:
                    importlib.import_module(f"{package}.{mod_name}")
                except ImportError as e:
                    logger.debug("module_import_skip", package=package, module=mod_name, error=str(e))


registry = ModuleRegistry()
