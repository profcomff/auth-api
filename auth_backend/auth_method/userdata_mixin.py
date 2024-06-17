from abc import ABCMeta, abstractmethod
from typing import Any, final

from event_schema.auth import UserLogin, UserLoginKey

from .base import AuthPluginMeta


class UserdataMixin(AuthPluginMeta, metaclass=ABCMeta):
    """Включает поддержку отправки данных о пользователе в сервис Userdata API

    Подробнее о Userdata API: https://github.com/profcomff/userdata-api
    """

    @staticmethod
    @final
    def generate_kafka_key(user_id: int) -> UserLoginKey:
        """
        Мы генерируем ключи так как для сообщений с одинаковыми ключами
        Kafka гарантирует последовательность чтений
        Args:
            user_id: Айди пользователя

        Returns:
            Ничего
        """
        return UserLoginKey.model_validate({"user_id": user_id})

    @classmethod
    @abstractmethod
    async def _convert_data_to_userdata_format(cls, data: Any) -> UserLogin:
        raise NotImplementedError()

    @classmethod
    def userdata_process_empty_strings(cls, userdata: UserLogin) -> UserLogin:
        """Изменяет значения с пустыми строками в параметре категории юзердаты на None"""
        for item in userdata.items:
            if item.value == '':
                item.value = None
        return userdata
