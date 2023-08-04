from abc import ABC, abstractmethod
from typing import Any

from fastapi import BackgroundTasks


class KafkaMeta(ABC):
    @abstractmethod
    async def produce(self, topic: str, value: Any, *, bg_tasks: BackgroundTasks) -> Any:
        raise NotImplementedError()
