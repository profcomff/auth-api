from __future__ import annotations

import logging
import random
import re
import string
from abc import ABCMeta, abstractmethod
from datetime import datetime

from fastapi import APIRouter, HTTPException
from fastapi_sqlalchemy import db
from pydantic import constr

from auth_backend.base import Base, ResponseModel
from auth_backend.models.db import User, UserSession, Scope, UserSessionScope
from auth_backend.settings import get_settings
from auth_backend.schemas.types.scopes import Scope as TypeScope
from sqlalchemy.orm import Session as DbSession


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
    fields: list[str] = []

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
    async def _create_session(user: User, scopes_list_names: list[TypeScope] | None, *, db_session: DbSession) -> Session:
        """Создает сессию пользователя"""
        scopes = set()
        if scopes_list_names is None:
            scopes = user.scopes
        else:
            scopes = await AuthMethodMeta.create_scopes_set_by_ids(scopes_list_names)
            await AuthMethodMeta._check_scopes(scopes, user)
        user_session = UserSession(user_id=user.id, token=random_string(length=settings.TOKEN_LENGTH))
        db_session.add(user_session)
        db_session.flush()
        for scope in scopes:
            db_session.add(UserSessionScope(scope_id=scope.id, user_session_id=user_session.id))
        db_session.commit()
        return Session(
            user_id=user_session.user_id,
            token=user_session.token,
            id=user_session.id,
            expires=user_session.expires,
            session_scopes=[_scope.name for _scope in user_session.scopes]
        )

    @staticmethod
    async def create_scopes_set_by_ids(scopes_list_names: list[TypeScope]) -> set[Scope]:
        scopes = set()
        for scope_name in scopes_list_names:
            scope = Scope.get_by_name(scope_name, session=db.session)
            scopes.add(scope)
        return scopes

    @staticmethod
    async def _check_scopes(scopes: set[Scope], user: User) -> None:
        if len(scopes & user.scopes) != len(scopes):
            raise HTTPException(
                status_code=403,
                detail=ResponseModel(
                    status="Error",
                    message=f"Incorrect user scopes, triggering scopes -> {[scope.name for scope in scopes - user.scopes]} ",
                ).json(),
            )

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


class OauthMeta(AuthMethodMeta):
    """Абстрактная авторизация и аутентификация через OAuth"""

    class UrlSchema(Base):
        url: str

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/redirect_url", self._redirect_url, methods=["GET"], response_model=self.UrlSchema)
        self.router.add_api_route("/auth_url", self._auth_url, methods=["GET"], response_model=self.UrlSchema)

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
