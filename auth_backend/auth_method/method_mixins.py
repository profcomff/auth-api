from abc import ABCMeta, abstractmethod

from sqlalchemy.orm import Session as DbSession

from auth_backend.auth_method.session import Session
from auth_backend.models.db import User
from auth_backend.schemas.types.scopes import Scope as TypeScope
from auth_backend.utils.user_session_control import create_session

from .base import AuthPluginMeta
from .session import Session


class RegistrableMixin(AuthPluginMeta, metaclass=ABCMeta):
    """Сообщает что AuthMethod поддерживает регистрацию

    Обязывает AuthMethod иметь метод `_register`, который используется как апи-запрос `/registration`
    """

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/registration", self._register, methods=["POST"])

    @staticmethod
    @abstractmethod
    async def _register(*args, **kwargs) -> object:
        raise NotImplementedError()

    @staticmethod
    async def _create_user(*, db_session: DbSession) -> User:
        """Создает пользователя"""
        user = User.create(session=db_session)
        db_session.flush()
        return user


class LoginableMixin(AuthPluginMeta, metaclass=ABCMeta):
    """Сообщает что AuthMethod поддерживает вход

    Обязывает AuthMethod иметь метод `_login`, который используется как апи-запрос `/login`
    """

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/login", self._login, methods=["POST"], response_model=Session)

    @staticmethod
    @abstractmethod
    async def _login(*args, **kwargs) -> Session:
        raise NotImplementedError()

    @staticmethod
    async def _create_session(
        user: User, scopes_list_names: list[TypeScope] | None, session_name: str | None = None, *, db_session: DbSession
    ) -> Session:
        """Создает сессию пользователя"""
        return await create_session(user, scopes_list_names, db_session=db_session, session_name=session_name)
