from __future__ import annotations

import logging
import re
from abc import ABCMeta, abstractmethod
from asyncio import gather
from typing import Any, Iterable, final

from event_schema.auth import UserLogin, UserLoginKey
from fastapi import APIRouter
from sqlalchemy.orm import Session as DbSession

from auth_backend.auth_method.session import Session
from auth_backend.models.db import User, UserSession
from auth_backend.schemas.types.scopes import Scope as TypeScope
from auth_backend.settings import get_settings
from auth_backend.utils.user_session_control import create_session


logger = logging.getLogger(__name__)
settings = get_settings()


AUTH_METHODS: dict[str, type[AuthMethodMeta]] = {}


class AuthMethodMeta(metaclass=ABCMeta):
    router: APIRouter
    prefix: str
    tags: list[str] = []

    @classmethod
    def get_name(cls) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    def __init__(self):
        self.router = APIRouter()
        self.router.add_api_route("/registration", self._register, methods=["POST"])
        self.router.add_api_route("/login", self._login, methods=["POST"], response_model=Session)

    def __init_subclass__(cls, **kwargs):
        if cls.__name__.endswith('Meta'):
            return
        logger.info(f'Init authmethod {cls.__name__}')
        AUTH_METHODS[cls.__name__] = cls

    @staticmethod
    @abstractmethod
    async def _register(*args, **kwargs) -> object:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    async def _login(*args, **kwargs) -> Session:
        raise NotImplementedError()

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

    @staticmethod
    async def _create_session(
        user: User, scopes_list_names: list[TypeScope] | None, session_name: str | None = None, *, db_session: DbSession
    ) -> Session:
        """Создает сессию пользователя"""
        return await create_session(user, scopes_list_names, db_session=db_session, session_name=session_name)

    @staticmethod
    async def _create_user(*, db_session: DbSession) -> User:
        """Создает пользователя"""
        user = User()
        db_session.add(user)
        db_session.flush()
        return user

    async def _get_user(
        *,
        db_session: DbSession,
        user_session: UserSession = None,
        session_token: str = None,
        user_id: int = None,
        with_deleted: bool = False,
        with_expired: bool = False,
    ):
        """Отдает пользователя по сессии, токену или user_id"""
        if user_id:
            return User.get(user_id, with_deleted=with_deleted, session=db_session)
        if session_token:
            user_session: UserSession = (
                UserSession.query(with_deleted=with_deleted, session=db_session)
                .filter(UserSession.token == session_token)
                .one_or_none()
            )
        if user_session and (not user_session.expired or with_expired):
            return user_session.user
        return

    @classmethod
    @abstractmethod
    async def _convert_data_to_userdata_format(cls, data: Any) -> UserLogin:
        raise NotImplementedError()

    @staticmethod
    async def user_updated(
        new_user: dict[str, Any] | None,
        old_user: dict[str, Any] | None = None,
    ):
        """Сообщить всем активированным провайдерам авторизации об обновлении пользователя

        Каждый AuthMethod должен вызывать эту функцию при создании или изменении пользователя, но
        не более одного раза на один запрос пользователя на изменение. При вызове во всех
        активированных (включенных в настройках) AuthMethod выполняется функция on_user_update.

        ## Diff-пользователя
        `new_user` и `old_user` – словари, представляющие изменения в данных пользователя.

        Если `new_user` равен `None`, то пользователь был удален. Если `old_user` равен `None`, то
        пользователь был создан. В остальных случаях словарь, в котором обязательно есть ключ
        `user_id`.

        Словарь может содержать ключи с названиями AuthMethod, в которых данные изменились. В
        значениях будут находиться словари с ключами `param` и значениями `value` параметров
        AuthMethod.

        ### Примеры:

        Пользователь id=1 был удален, вместе с ним были удалены параметры email метода Email и
        user_id метода GitHub.
        ```python
        new_user = None
        old_user = {'user_id': 1, "email": {"email": "user@example.com"}, "github": {"user_id": "123"}}
        ```

        Пользователь id=2 сменил пароль.
        ```python
        new_user = {
            "user_id": 2,
            "email": {"hashed_password": "somerandomshit", "salt": "blahblah"}
        }
        old_user = {
            "user_id": 2,
            "email": {"hashed_password": "tihsmodnaremos", "salt": "abracadabra", "password": "plain_password"}
        }
        ```
        """
        exceptions = await gather(
            *[m.on_user_update(new_user, old_user) for m in AuthMethodMeta.active_auth_methods()],
            return_exceptions=True,
        )
        if len(exceptions) > 0:
            logger.error("Following errors occurred during on_user_update: ")
            for exc in exceptions:
                logger.error(exc)

    @staticmethod
    async def on_user_update(new_user: dict[str, Any], old_user: dict[str, Any] | None = None):
        """Произвести действия на обновление пользователя, в т.ч. обновление в других провайдерах

        Описания входных параметров соответствует параметрам `AuthMethodMeta.user_updated`.
        """

    @classmethod
    def is_active(cls):
        return settings.ENABLED_AUTH_METHODS is None or cls.get_name() in settings.ENABLED_AUTH_METHODS

    @staticmethod
    def active_auth_methods() -> Iterable[type['AuthMethodMeta']]:
        for method in AUTH_METHODS.values():
            if method.is_active():
                yield method
