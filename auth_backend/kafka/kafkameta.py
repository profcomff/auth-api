from abc import ABC, abstractmethod
from typing import Any


class KafkaMeta(ABC):
    @abstractmethod
    async def produce(self, topic: str, value: Any, *, action: str) -> Any:
        raise NotImplementedError()

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError()
