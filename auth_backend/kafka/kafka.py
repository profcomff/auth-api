import logging
from functools import lru_cache
from typing import Any

from confluent_kafka import KafkaException, Producer
from fastapi import BackgroundTasks

from auth_backend import __version__
from auth_backend.kafka.kafkameta import KafkaMeta
from auth_backend.settings import get_settings


log = logging.getLogger(__name__)


class AIOKafka(KafkaMeta):
    __dsn = get_settings().KAFKA_DSN
    __devel: bool = True if __version__ == "dev" else False
    __conf: dict[str, str] = {}
    __timeout: int = get_settings().KAFKA_TIMEOUT
    __login: str | None = get_settings().KAFKA_LOGIN
    __password: str | None = get_settings().KAFKA_PASSWORD
    _producer: Producer

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
        self.__configurate()
        self._producer = Producer(self.__conf)
        self._cancelled = False

    def delivery_callback(self, err, msg):
        if err:
            log.error('%% Message failed delivery: %s\n' % err)
        else:
            log.info('%% Message delivered to %s [%d] @ %d\n' % (msg.topic(), msg.partition(), msg.offset()))

    def _produce(self, topic: str, value: Any) -> Any:
        try:
            self._producer.produce(topic, value, callback=self.delivery_callback)
        except KafkaException:
            log.critical("Kafka is down")

        self._producer.poll(0)

    async def produce(self, topic: str, value: Any, *, bg_tasks: BackgroundTasks) -> Any:
        bg_tasks.add_task(self._produce, topic, value)


class AIOKafkaMock(KafkaMeta):
    async def produce(self, topic: str, value: Any, *, bg_tasks: BackgroundTasks) -> Any:
        log.debug(f"Kafka cluster disabled, debug msg: {topic=}, {value=}")


@lru_cache
def producer() -> KafkaMeta:
    if get_settings().KAFKA_DSN:
        return AIOKafka()
    return AIOKafkaMock()
