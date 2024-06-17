import logging
from abc import abstractmethod

from fastapi import Depends
from fastapi_sqlalchemy import db
from sqlalchemy.orm import Session as DbSession

from auth_backend.base import Base
from auth_backend.exceptions import LastAuthMethodDelete
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.utils.security import UnionAuth

from .base import AuthMethodMeta
from .method_mixins import LoginableMixin, RegistrableMixin
from .userdata_mixin import UserdataMixin


logger = logging.getLogger(__name__)


class OauthMeta(UserdataMixin, LoginableMixin, RegistrableMixin, AuthMethodMeta):
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
        old_user = {"user_id": user_session.user.id}
        new_user = {"user_id": user_session.user.id}
        old_user_params = await cls._delete_auth_methods(user_session.user, db_session=db.session)
        old_user[cls.get_name()] = old_user_params
        await AuthMethodMeta.user_updated(new_user, old_user)
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
    async def _register_auth_method(cls, key: str, value: str | int, user: User, *, db_session) -> AuthMethod:
        """Добавление пользователю новый AuthMethod"""
        return AuthMethod.create(
            user_id=user.id,
            auth_method=cls.get_name(),
            param=key,
            value=str(value),
            session=db_session,
        )

    @classmethod
    async def _delete_auth_methods(cls, user: User, *, db_session) -> list[AuthMethod]:
        """Удаляет пользователю все AuthMethod конкретной авторизации"""
        auth_methods: list[AuthMethod] = (
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
        return {m.param: m.value for m in auth_methods}
