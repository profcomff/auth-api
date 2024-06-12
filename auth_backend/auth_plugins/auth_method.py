from __future__ import annotations

import logging
import random
import re
import string
from abc import ABCMeta, abstractmethod
from datetime import datetime
from typing import Any, final

from event_schema.auth import UserLogin, UserLoginKey
from fastapi import APIRouter, Depends
from fastapi_sqlalchemy import db
from pydantic import constr
from sqlalchemy.orm import Session as DbSession

from auth_backend.base import Base
from auth_backend.exceptions import AlreadyExists, LastAuthMethodDelete
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope as TypeScope
from auth_backend.settings import get_settings
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.user_session_control import create_session


logger = logging.getLogger(__name__)
settings = get_settings()


def random_string(length: int = 32) -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(length)])


class Session(Base):
    token: constr(min_length=1)
    expires: datetime
    id: int
    user_id: int
    session_scopes: list[TypeScope]


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


class OauthMeta(AuthMethodMeta):
    """Абстрактная авторизация и аутентификация через OAuth"""

    class UrlSchema(Base):
        url: str

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/redirect_url", self._redirect_url, methods=["GET"], response_model=self.UrlSchema)
        self.router.add_api_route("/auth_url", self._auth_url, methods=["GET"], response_model=self.UrlSchema)
        self.router.add_api_route("", self._unregister, methods=["DELETE"])

    @staticmethod
    @abstractmethod
    async def _redirect_url(*args, **kwargs) -> UrlSchema:
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    async def _auth_url(*args, **kwargs) -> UrlSchema:
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        raise NotImplementedError()

    @classmethod
    async def _unregister(cls, user_session: UserSession = Depends(UnionAuth(scopes=[], auto_error=True))):
        """Отключает для пользователя метод входа"""
        await cls._delete_auth_methods(user_session.user, db_session=db.session)
        return None

    @classmethod
    async def _get_user(cls, key: str, value: str | int, *, db_session: DbSession) -> User | None:
        auth_method: AuthMethod = (
            AuthMethod.query(session=db_session)
            .filter(
                AuthMethod.param == key,
                AuthMethod.value == str(value),
                AuthMethod.auth_method == cls.get_name(),
            )
            .limit(1)
            .one_or_none()
        )
        if auth_method:
            return auth_method.user

    @classmethod
    async def _register_auth_method(cls, key: str, value: str | int, user: User, *, db_session):
        """Добавление пользователю новый AuthMethod"""
        AuthMethod.create(
            user_id=user.id,
            auth_method=cls.get_name(),
            param=key,
            value=str(value),
            session=db_session,
        )

    @classmethod
    async def _delete_auth_methods(cls, user: User, *, db_session):
        """Удаляет пользователю все AuthMethod конкретной авторизации"""
        auth_methods = (
            AuthMethod.query(session=db_session)
            .filter(
                AuthMethod.user_id == user.id,
                AuthMethod.auth_method == cls.get_name(),
            )
            .all()
        )
        all_auth_methods = AuthMethod.query(session=db_session).filter(AuthMethod.user_id == user.id).all()
        if len(all_auth_methods) - len(auth_methods) == 0:
            raise LastAuthMethodDelete()
        logger.debug(auth_methods)
        for method in auth_methods:
            method.is_deleted = True
        db_session.flush()

    @classmethod
    def userdata_process_empty_strings(cls, userdata: UserLogin) -> UserLogin:
        '''Изменяет значения с пустыми строками в параметре категории юзердаты на None'''
        for item in userdata.items:
            if item.value == '':
                item.value = None
        return userdata
