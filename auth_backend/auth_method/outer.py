import logging
from abc import ABCMeta, abstractmethod
from typing import Any

from event_schema.auth import UserLoginKey
from fastapi import Depends
from fastapi.background import BackgroundTasks
from fastapi.exceptions import HTTPException
from fastapi_sqlalchemy import db
from starlette.status import HTTP_403_FORBIDDEN, HTTP_404_NOT_FOUND, HTTP_409_CONFLICT, HTTP_424_FAILED_DEPENDENCY

from auth_backend.auth_method.base import AuthPluginMeta
from auth_backend.base import Base
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import AuthMethod, UserSession
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


class ConnectionIssue(HTTPException, OuterAuthException):
    """Ошибка запроса к внешнему сервису"""

    def __init__(self, user_id):
        super().__init__(status_code=HTTP_424_FAILED_DEPENDENCY, detail=f"User id={user_id} not linked")


class UserLinkingForbidden(HTTPException, OuterAuthException):
    """У пользователя недостаточно прав для привязки аккаунта к внешнему сервису"""

    def __init__(self):
        super().__init__(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")


class GetOuterAccount(Base):
    username: str


class LinkOuterAccount(Base):
    username: str


class OuterAuthMeta(AuthPluginMeta, metaclass=ABCMeta):
    """Позволяет подключить внешний сервис для синхронизации пароля"""

    _BASE_SCOPE: str

    def __new__(cls, *args, **kwargs):
        cls._BASE_SCOPE = f"auth.{cls.get_name()}.link"
        logger.info(
            f"Init authmethod {cls.get_name()}, scopes: %s, %s, %s",
            cls.get_scope(),
            cls.post_scope(),
            cls.delete_scope(),
        )
        return super().__new__(cls)

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/{user_id}/link", self._get_link, methods=["GET"])
        self.router.add_api_route("/{user_id}/link", self._link, methods=["POST"])
        self.router.add_api_route("/{user_id}/link", self._unlink, methods=["DELETE"])

    @classmethod
    def get_scope(cls):
        """Права, необходимые пользователю для получения данных о внешнем аккаунте"""
        return cls._BASE_SCOPE + ".read"

    @classmethod
    def post_scope(cls):
        """Права, необходимые пользователю для создания данных о внешнем аккаунте"""
        return cls._BASE_SCOPE + ".create"

    @classmethod
    def delete_scope(cls):
        """Права, необходимые пользователю для удаления данных о внешнем аккаунте"""
        return cls._BASE_SCOPE + ".delete"

    @classmethod
    @abstractmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя во внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в внешнем сервисе"""
        raise NotImplementedError()

    @classmethod
    async def __get_username(cls, user_id: int) -> AuthMethod:
        auth_params = cls.get_auth_method_params(user_id, session=db.session)
        username = auth_params.get("username")
        if not username:
            logger.debug("User user_id=%d have no username in outer service %s", user_id, cls.get_name())
            return
        return username

    @classmethod
    async def on_user_update(cls, new_user: dict[str, Any], old_user: dict[str, Any] | None = None):
        """Произвести действия на обновление пользователя, в т.ч. обновление в других провайдерах

        Описания входных параметров соответствует параметрам `AuthMethodMeta.user_updated`.
        """
        # logger.debug("on_user_update class=%s started, new_user=%s, old_user=%s", cls.get_name(), new_user, old_user)
        if not new_user or not old_user:
            # Пользователь был только что создан или удален
            # Тут не будет дополнительных методов
            logger.debug("%s not new_user or not old_user, closing", cls.get_name())
            return

        user_id = new_user.get("user_id")
        password = new_user.get("email", {}).get("password")
        if not password:
            # В этом событии пароль не обновлялся, ничего не делаем
            logger.debug("%s not password, closing", cls.get_name())
            return

        username = await cls.__get_username(user_id)
        if not username:
            # У пользователя нет имени во внешнем сервисе
            logger.debug("%s not username, closing", cls.get_name())
            return

        if await cls._is_outer_user_exists(username.value):
            logger.debug("%s user exists, changing password", cls.get_name())
            await cls._update_outer_user_password(username.value, password)
        else:
            # Мы не нашли этого пользователя во внешнем сервисе
            # Разорвем связку и кинем лог
            logger.debug("%s user not exists, unlinking", cls.get_name())
            username.is_deleted = True
            logger.error(
                "User id=%d has username %s, which can't be found in %s",
                user_id,
                username.value,
                cls.get_name(),
            )
        logger.debug("on_user_update class=%s finished", cls.get_name())

    @classmethod
    async def _get_link(
        cls,
        user_id: int,
        request_user: UserSession = Depends(UnionAuth()),
    ) -> GetOuterAccount:
        """Получить данные внешнего аккаунт пользователя

        Получить данные может администратор или сам пользователь
        """
        if cls.get_scope() not in (s.name for s in request_user.scopes) and request_user.id != user_id:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = await cls.__get_username(user_id)
        if not username:
            raise UserNotLinked(user_id)
        return GetOuterAccount(username=username.value)

    @classmethod
    async def _link(
        cls,
        user_id: int,
        outer: LinkOuterAccount,
        request_user: UserSession = Depends(UnionAuth()),
    ) -> GetOuterAccount:
        """Привязать пользователю внешний аккаунт

        Привязать аккаунт может только администратор
        """
        if cls.post_scope() not in (s.name for s in request_user.scopes):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = await cls.__get_username(user_id)
        if username:
            raise UserLinkingConflict(user_id)
        param = cls.create_auth_method_param("username", outer.username, user_id, db_session=db.session)
        result = GetOuterAccount(username=param.value)
        db.session.commit()
        return result

    @classmethod
    async def _unlink(
        cls,
        user_id: int,
        background_tasks: BackgroundTasks,
        request_user: UserSession = Depends(UnionAuth()),
    ):
        """Отвязать внешний аккаунт пользователю

        Удалить данные может администратор
        """
        if cls.delete_scope() not in (s.name for s in request_user.scopes):
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        username = await cls.__get_username(user_id)
        if not username:
            raise UserNotLinked(user_id)
        username.is_deleted = True
        db.session.commit()
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            UserLoginKey(user_id=user_id, auth_method=cls.get_name()),
            None,
        )
