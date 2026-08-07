from abc import ABC, abstractmethod
from typing import Any

from core.engine import BaseModule, registry


class BaseDetector(BaseModule, ABC):
    mode = "detection"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name != "base_detector":
            registry.register_detection(cls)

    @abstractmethod
    async def run(self, **kwargs: Any) -> None:
        ...
