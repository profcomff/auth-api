import logging
from abc import ABCMeta, abstractmethod
from typing import Any

from fastapi import Depends
from fastapi.exceptions import HTTPException
from fastapi_sqlalchemy import db
from starlette.status import HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from auth_backend.auth_method.base import AuthPluginMeta
from auth_backend.base import Base
from auth_backend.models.db import UserSession
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)


class OuterAuthException(Exception):
    """Базовый класс для исключений внешнего сервиса"""


class UserLinkingConflict(HTTPException, OuterAuthException):
    """Пользователь уже привязан к другому аккаунту"""

    def __init__(self, user_id):
        super().__init__(status_code=HTTP_409_CONFLICT, detail=f"User id={user_id} already linked")


class UserNotLinked(HTTPException, OuterAuthException):
    """Пользователь не привязан к аккаунту"""

    def __init__(self, user_id):
        super().__init__(status_code=HTTP_404_NOT_FOUND, detail=f"User id={user_id} not linked")


class UserLinkingForbidden(HTTPException, OuterAuthException):
    """У пользователя недостаточно прав для привязки аккаунта к внешнему сервису"""

    def __init__(self):
        super().__init__(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")


class GetOuterAccount(Base):
    username: str


class LinkOuterAccount(Base):
    username: str
    force_create: bool = False


class UnlinkOuterAccount(Base):
    force_delete: bool = False


class OuterAuthMeta(AuthPluginMeta, metaclass=ABCMeta):
    """Позволяет подключить внешний сервис для синхронизации пароля"""

    __BASE_SCOPE: str

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/{user_id}/link", self._get_link, methods=["GET"])
        self.router.add_api_route("/{user_id}/link", self._link, methods=["POST"])
        self.router.add_api_route("/{user_id}/unlink", self._unlink, methods=["DELETE"])
        self.__BASE_SCOPE = f"auth.{self.get_name()}.link"

    @classmethod
    def get_scope(cls):
        """Права, необходимые пользователю для получения данных о внешнем аккаунте"""
        return cls.__BASE_SCOPE + ".read"

    @classmethod
    def post_scope(cls):
        """Права, необходимые пользователю для создания данных о внешнем аккаунте"""
        return cls.__BASE_SCOPE + ".create"

    @classmethod
    def delete_scope(cls):
        """Права, необходимые пользователю для удаления данных о внешнем аккаунте"""
        return cls.__BASE_SCOPE + ".delete"

    @classmethod
    @abstractmethod
    async def _is_outer_user_exists(cls, username):
        """Проверяет наличие пользователя во внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _create_outer_user(cls, username, password):
        """Создает пользователя в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _delete_outer_user(cls, username):
        """Отключает (если возможно) или удаляет пользователя в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _update_outer_user_password(cls, username, password):
        """Устанавливает пользователю новый пароль в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    async def __get_username(cls, user_id):
        auth_params = cls.get_auth_method_params(user_id, session=db.session)
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
            if await cls._is_outer_user_exists(username):
                await cls._delete_outer_user(username)
        except Exception as exc:
            logger.error("Error occured while deleting outer user", exc_info=1)
            raise exc

    @classmethod
    async def __try_create_user(cls, username, password):
        try:
            await cls._create_outer_user(username, password)
        except Exception as exc:
            logger.error("Error occured while creating outer user", exc_info=1)
            raise exc

    @classmethod
    async def __try_update_user(cls, username, password):
        try:
            await cls._update_outer_user_password(username, password)
        except Exception as exc:
            logger.error("Error occured while updating outer user", exc_info=1)
            raise exc

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

        if await cls._is_outer_user_exists(username):
            await cls.__try_update_user(username, password)
        else:
            # Если пользователя нет во внешнем сервисе, создать его
            await cls.__try_create_user(username, password)

    @classmethod
    def _get_link(
        cls,
        user_id,
        request_user: UserSession = Depends(UnionAuth()),
    ) -> GetOuterAccount:
        """Получить данные внешнего аккаунт пользователя

        Получить данные может администратор или сам пользователь
        """
        if cls.get_scope() not in (s.name for s in request_user.scopes) and request_user.id != user_id:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = cls.__get_username(user_id)
        if not username:
            raise UserNotLinked(user_id)
        return GetOuterAccount(username=username.value)

    @classmethod
    async def _link(
        cls,
        user_id,
        outer: LinkOuterAccount,
        request_user: UserSession = Depends(UnionAuth()),
    ) -> GetOuterAccount:
        """Привязать пользователю внешний аккаунт

        Привязать аккаунт может только администратор
        """
        if cls.post_scope() not in (s.name for s in request_user.scopes):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = cls.__get_username(user_id)
        if username:
            raise UserLinkingConflict(user_id)
        param = cls.create_auth_method_param("username", outer.username, user_id, db_session=db.session)
        if outer.force_create:
            if not await cls._is_outer_user_exists(outer.username):
                await cls.__try_create_user(user_id)
        db.session.commit()
        return GetOuterAccount(username=param.value)

    @classmethod
    async def _unlink(
        cls,
        user_id,
        outer: UnlinkOuterAccount,
        request_user: UserSession = Depends(UnionAuth()),
    ):
        """Отвязать внешний аккаунт пользователю

        Удалить данные может администратор
        """
        if cls.delete_scope() not in (s.name for s in request_user.scopes):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = cls.__get_username(user_id)
        if not username:
            raise UserNotLinked(user_id)
        username.is_deleted = True
        if outer.force_delete:
            if await cls._is_outer_user_exists(username):
                await cls.__try_delete_user(user_id)
        db.session.commit()
