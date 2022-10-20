import re
from abc import abstractmethod, ABCMeta
from fastapi import APIRouter
from .models.base import Session


class AuthMethodMeta(metaclass=ABCMeta):
    FIELDS: list[str]
    router: APIRouter

    @classmethod
    def get_name(cls) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    def __init__(self):
        self.router = APIRouter(prefix=f"/{AuthMethodMeta.get_name()}")
        self.router.add_api_route("/registration", self.registrate, methods=["POST"])
        self.router.add_api_route("/login", self.login, methods=["POST"], response_model=Session)


    @abstractmethod
    async def register_flow(self, **kwargs):
        raise NotImplementedError()

    @abstractmethod
    async def login_flow(self, **kwargs):
        raise NotImplementedError()

    async def registrate(self, **kwargs) -> object:
        return await self.register_flow(**kwargs)

    async def login(self, **kwargs) -> Session:
        return Session.from_orm(await self.login_flow(**kwargs))





