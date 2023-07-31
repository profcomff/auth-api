import asyncio
import logging
from functools import lru_cache
from threading import Thread
from typing import Any

from confluent_kafka import KafkaException, Producer

from auth_backend import __version__
from auth_backend.kafka.kafkameta import KafkaMeta
from auth_backend.settings import get_settings


log = logging.getLogger(__name__)


class AIOKafka(KafkaMeta):
    __dsn = get_settings().KAFKA_DSN
    __devel: bool = True if __version__ == "dev" else False
    __conf: dict[str, str] = {}
    __timeout: int = get_settings().KAFKA_TIMEOUT
    __login: str = get_settings().KAFKA_LOGIN
    __password: str = get_settings().KAFKA_PASSWORD

    def __configurate(self) -> None:
        if self.__devel:
            self.__conf = {"bootstrap.servers": self.__dsn}
        else:
            self.__conf = {
                'bootstrap.servers': self.__dsn,
                'sasl.mechanisms': "PLAIN",
                'security.protocol': "SASL_PLAINTEXT",
                'sasl.username': self.__login,
                'sasl.password': self.__password,
            }

    def __init__(self) -> None:
        self._poll_thread = Thread(target=self._poll_loop, daemon=True)
        self.__configurate()
        self._producer = Producer(self.__conf)
        self._cancelled = False
        self._poll_thread.start()

    def _poll_loop(self) -> None:
        while not self._cancelled:
            self._producer.poll(0.1)

    def close(self) -> None:
        self._producer.flush()
        self._cancelled = True
        self._poll_thread.join()

    def _produce(self, topic: str, value: Any) -> asyncio.Future:
        loop = asyncio.get_running_loop()
        result = loop.create_future()

        if not self.__dsn:
            loop.call_soon_threadsafe(result.set_result, "Kafka DSN is None")
            return result

        def callback(err: Exception, msg: str):
            if err:
                loop.call_soon_threadsafe(result.set_exception, KafkaException(err))
            else:
                loop.call_soon_threadsafe(result.set_result, msg)

        self._producer.produce(topic, value, on_delivery=callback)
        return result

    async def produce(self, topic: str, value: Any) -> Any:
        try:
            return await asyncio.wait_for(self._produce(topic, value), timeout=self.__timeout)
        except asyncio.TimeoutError:
            log.critical(f"Kafka is down, timeout error occurred")


class AIOKafkaMock(KafkaMeta):
    async def produce(self, topic: str, value: Any) -> Any:
        pass

    def close(self) -> None:
        pass


@lru_cache
def producer() -> KafkaMeta:
    if get_settings().KAFKA_DSN:
        return AIOKafka()
    return AIOKafkaMock()
