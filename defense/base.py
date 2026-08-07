from abc import ABC, abstractmethod
from typing import Any

from core.engine import BaseModule, registry


class BaseDefender(BaseModule, ABC):
    mode = "defense"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name != "base_defender":
            registry.register_defense(cls)

    @abstractmethod
    async def run(self, **kwargs: Any) -> None:
        ...
