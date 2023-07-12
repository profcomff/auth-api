from __future__ import annotations

import logging
import random
import re
import string
from abc import ABCMeta, abstractmethod
from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi_sqlalchemy import db
from pydantic import constr
from sqlalchemy.orm import Session as DbSession

from auth_backend.base import Base
from auth_backend.exceptions import AlreadyExists
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


class MethodMeta(metaclass=ABCMeta):
    """Параметры метода аввторизации пользователя
    Args:
        `__fields__: frozenset - required` - множество параметров данного метода авторизации

        `__required_fields__: frozenset - required` - множество обязательных парамтеров данного метода авторизации

        `__auth_method__: str - required` - __repr__ соотвествуещго метода авторизации

    Пример:
    ```
    class YourAuthParams(MethodMeta):
        __auth_method__ = "your_auth" ##YourAuth.__repr__ === "your_auth"

        __fields__ = frozenset(frozenset(("very_important_field", "not_important_field",))("very_important_field", "not_important_field",))

        __required_fields__ = frozenset(("very_important_field",))
    ```
    """

    __auth_method__: str = None

    __fields__ = frozenset()
    __required_fields__ = frozenset()
    __user: User

    def __init__(self, user: User, methods: list[AuthMethod] = None):
        assert self.__fields__ and self.__required_fields__, "__fields__ or  __required_fields__ not defined"
        if methods is None:
            methods = []
        self.__user = user
        for method in methods:
            assert method.param in self.__fields__
            setattr(self, method.param, method)

    async def create(self, param: str, value: str) -> AuthMethod:
        """
        Создает AuthMethod у данного юзера, auth_method берется из
        self.__auth_method__

        Args:
            param: str - параметр AuthMethod

            value: str - значение, которое будет задано по этому параметру

        Returns:
            AuthMethod - созданный метод

        Raises:
            AssertionError - если param не нахяодятся в __fields__

            AlreadyExists - если метод по такому ключу уже существует

        Пример:
        ```
        user.auth_methods.email.create("email", value)
        ```
        """
        assert param in self.__fields__, "You cant create auth_method which not declared in __fields__"
        if attr := getattr(self, param):
            raise AlreadyExists(attr, attr.id)
        _method = AuthMethod(
            user_id=self.__user.id, param=param, value=value, auth_method=self.__class__.get_auth_method_name()
        )
        assert param in self.__fields__, "You cant create auth_method which not daclared"
        db.session.add(_method)
        db.session.flush()
        db.session.refresh(self.__user)
        setattr(self, param, _method)
        return _method

    async def bulk_create(self, map: dict[str, str]) -> list[AuthMethod]:
        """Создает несколько AuthMethod'ов по мапе param-value,
        auth_method берется из self.__auth_method__

        Args:
            map: dict[str, str] - словарь, по которому будуут создаваться AuthMthods

        Returns:
            list[AuthMethod] - созданные методы

        Raises:
            AssertionError - если ключи словаря не нахяодятся в ___fields__

            AlreadyExists - если метод по такому ключу уже существует

        Пример:
        ```
        user.auth_method.email.bulk_create({"email": val1, "salt": val2})
        ```
        """
        for k in map.keys():
            assert k in self.__fields__, "You cant create auth_method which not declared in __fields__"
            if attr := getattr(self, k):
                raise AlreadyExists(attr, attr.id)
        methods: list[AuthMethod] = []
        for k, v in map.items():
            methods.append(
                method := AuthMethod(
                    user_id=self.__user.id, param=k, value=v, auth_method=self.__class__.get_auth_method_name()
                )
            )
            db.session.add(method)
        db.session.flush()
        db.session.refresh(self.__user)
        return methods

    def __bool__(self) -> bool:
        """Определен ли для польщователя этот метод аутентификации
        Args:
             None
        Returns:
            Если у юзера удалено/не определено хотя бы одно из полей из
            __required_fields__ -> False, иначе True

        """
        for field in self.__required_fields__:
            if not getattr(self, field):
                return False
        return True

    @classmethod
    def get_auth_method_name(cls) -> str:
        """Имя соответствующего метода аутентфикации

        Args:
            None

        Returns:
            Имя метода аутентификации, к которому
            приилагается данный класс
        """
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__auth_method__).lower()


class AuthMethodMeta(metaclass=ABCMeta):
    router: APIRouter
    prefix: str
    tags: list[str] = []

    fields: type[AuthMethodMeta] = MethodMeta

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
    async def _create_session(
        user: User, scopes_list_names: list[TypeScope] | None, session_name: str = None, *, db_session: DbSession
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
        logger.debug(auth_methods)
        for method in auth_methods:
            method.is_deleted = True
        db_session.flush()
