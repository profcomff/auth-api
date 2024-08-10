from abc import ABC, abstractmethod
from typing import Any


class KafkaMeta(ABC):
    @abstractmethod
    def produce(self, topic: str, key: Any, value: Any) -> Any:
        raise NotImplementedError()

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError()
