import logging
from abc import ABCMeta, abstractmethod
from typing import Any

from fastapi_sqlalchemy import db

from auth_backend.auth_method.base import AuthPluginMeta
from auth_backend.utils.auth_params import get_auth_params


logger = logging.getLogger(__name__)


class OuterAuthException(Exception):
    """Базовый класс для исключений внешнего сервиса"""


class OuterAuthCommunicationException(OuterAuthException):
    """Ошибка коммуникации с внешним сервисом"""


class OuterAuthMeta(AuthPluginMeta, metaclass=ABCMeta):
    """Позволяет подключить внешний сервис для синхронизации пароля"""

    @classmethod
    @abstractmethod
    async def _is_user_exists(cls, username):
        """Проверяет наличие пользователя во внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _create_user(cls, username, password):
        """Создает пользователя в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _delete_user(cls, username):
        """Отключает (если возможно) или удаляет пользователя в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _update_user_password(cls, username, password):
        """Устанавливает пользователю новый пароль в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    async def __get_username(cls, user_id):
        auth_params = get_auth_params(user_id, cls.get_name(), db.session)
        username = auth_params.get("username")
        if not username:
            logger.debug("User user_id=%d have no username in outer service %s", user_id, cls.get_name())
        return username.value

    @classmethod
    async def __try_delete_user(cls, user_id):
        try:
            username = await cls.__get_username(user_id)
            if not username:
                logger.debug("User user_id=%d have no username in outer service %s", user_id, cls.get_name())
                return
            if await cls._is_user_exists(username):
                await cls._delete_user(username)
        except Exception as exc:
            logger.error("Error occured while deleting outer user", exc_info=1)
            raise OuterAuthCommunicationException() from exc

    @classmethod
    async def __try_create_user(cls, username, password):
        try:
            await cls._create_user(username, password)
        except Exception as exc:
            logger.error("Error occured while creating outer user", exc_info=1)
            raise OuterAuthCommunicationException() from exc

    @classmethod
    async def __try_update_user(cls, username, password):
        try:
            await cls._update_user_password(username, password)
        except Exception as exc:
            logger.error("Error occured while updating outer user", exc_info=1)
            raise OuterAuthCommunicationException() from exc

    @classmethod
    async def on_user_update(cls, new_user: dict[str, Any], old_user: dict[str, Any] | None = None):
        """Произвести действия на обновление пользователя, в т.ч. обновление в других провайдерах

        Описания входных параметров соответствует параметрам `AuthMethodMeta.user_updated`.
        """
        if not new_user:
            # Пользователь удален в аутхе, удалить его во внешнем сервисе
            if not old_user:
                logger.error("Fail to obtain username, old and new user are empty")
            else:
                user_id = old_user.get("user_id")
                await cls.__try_delete_user(user_id)
            return

        user_id = new_user.get("user_id")
        password = new_user.get("email", {}).get("password")
        if not password:
            # В этом событии пароль не обновлялся, ничего не делаем
            return

        username = await cls.__get_username(user_id)
        if not username:
            # У пользователя нет имени во внешнем сервисе
            return

        if await cls._is_user_exists(username):
            await cls.__try_update_user(username, password)
        else:
            # Если пользователя нет во внешнем сервисе, создать его
            await cls.__try_create_user(username, password)
