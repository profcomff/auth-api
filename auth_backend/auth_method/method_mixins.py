from abc import ABCMeta, abstractmethod

from .base import AuthMethodMeta
from .session import Session


class RegistrableMixin(AuthMethodMeta, metaclass=ABCMeta):
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


class LoginableMixin(AuthMethodMeta, metaclass=ABCMeta):
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
