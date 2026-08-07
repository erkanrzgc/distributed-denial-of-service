from abc import ABC, abstractmethod
from typing import Any

from core.engine import BaseModule, registry


class BaseAttacker(BaseModule, ABC):
    mode = "attack"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name != "base_attacker":
            registry.register_attack(cls)

    @abstractmethod
    async def run(self, **kwargs: Any) -> None:
        ...
