from __future__ import annotations

import re
from abc import abstractmethod, ABCMeta

from fastapi import APIRouter

from pydantic import BaseModel
from datetime import datetime


class Base(BaseModel):
    def __repr__(self) -> str:
        attrs = []
        for k, v in self.__class__.schema().items():
            attrs.append(f"{k}={v}")
        return "{}({})".format(self.__class__.__name__, ', '.join(attrs))

    class Config:
        orm_mode = True


class Session(Base):
    expires: datetime
    id: int
    user_id: int
    token: str


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
        self.router.add_api_route("/registration", self.register, methods=["POST"])
        self.router.add_api_route("/login", self.login, methods=["POST"], response_model=Session)

    def __init_subclass__(cls, **kwargs):
        AUTH_METHODS[cls.__name__] = cls

    @staticmethod
    @abstractmethod
    async def register(**kwargs) -> object:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    async def login(**kwargs) -> Session:
        raise NotImplementedError()

