from __future__ import annotations

import logging
import re
from abc import ABCMeta
from asyncio import gather
from typing import Any, Iterable

from fastapi import APIRouter
from sqlalchemy.orm import Session as DbSession
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import get_settings


logger = logging.getLogger(__name__)
settings = get_settings()


AUTH_METHODS: dict[str, type[AuthPluginMeta]] = {}


class AuthPluginMeta(metaclass=ABCMeta):
    router: APIRouter
    prefix: str
    tags: list[str] = []

    @classmethod
    def get_name(cls) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    def __init__(self):
        self.router = APIRouter()

    def __init_subclass__(cls, **kwargs):
        if cls.__name__.endswith('Meta') or cls.__name__.endswith('Mixin'):
            return
        logger.info(f'Init authmethod {cls.__name__}')
        AUTH_METHODS[cls.__name__] = cls

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
            *[m.on_user_update(new_user, old_user) for m in AuthPluginMeta.active_auth_methods()],
            return_exceptions=True,
        )
        exceptions = [exc for exc in exceptions if exc]
        if len(exceptions) > 0:
            logger.error("Following errors occurred during on_user_update: ")
            for exc in exceptions:
                logger.error(exc, exc_info=exc)

    @classmethod
    async def on_user_update(cls, new_user: dict[str, Any], old_user: dict[str, Any] | None = None):
        """Произвести действия на обновление пользователя, в т.ч. обновление в других провайдерах

        Описания входных параметров соответствует параметрам `AuthMethodMeta.user_updated`.
        """

    @classmethod
    def is_active(cls):
        return settings.ENABLED_AUTH_METHODS is None or cls.get_name() in settings.ENABLED_AUTH_METHODS

    @staticmethod
    def active_auth_methods() -> Iterable[type['AuthPluginMeta']]:
        for method in AUTH_METHODS.values():
            if method.is_active():
                yield method

    @classmethod
    def create_auth_method_param(
        cls,
        key: str,
        value: str | int,
        user_id: int,
        *,
        db_session: DbSession,
    ) -> AuthMethod:
        """Добавление пользователю новый AuthMethod"""
        return AuthMethod.create(
            user_id=user_id,
            auth_method=cls.get_name(),
            param=key,
            value=str(value),
            session=db_session,
        )

    @classmethod
    def get_auth_method_params(
        cls,
        user_id: int,
        *,
        session: DbSession,
    ) -> dict[str, AuthMethod]:
        retval: dict[str, AuthMethod] = {}
        methods: list[AuthMethod] = (
            AuthMethod.query(session=session)
            .filter(
                AuthMethod.user_id == user_id,
                AuthMethod.auth_method == cls.get_name(),
            )
            .all()
        )
        for method in methods:
            retval[method.param] = method
        return retval
