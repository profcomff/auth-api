from __future__ import annotations

import re
from abc import abstractmethod, ABCMeta
from datetime import datetime

from fastapi import APIRouter
from pydantic import constr
from sqlalchemy.orm import relationship
from sqlalchemy.orm.collections import attribute_mapped_collection

from auth_backend.base import Base
from auth_backend.models.db import User


class Session(Base):
    token: constr(min_length=1)
    expires: datetime
    id: int
    user_id: int


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
        self.router.add_api_route("/registration", self.register, methods=["POST"])
        self.router.add_api_route("/login", self.login, methods=["POST"], response_model=Session)

    def __init_subclass__(cls, **kwargs):
        AUTH_METHODS[cls.__name__] = cls
        setattr(
            User,
            f"{cls.__name__}__{cls.get_name()}",
            relationship(
                "AuthMethod",
                foreign_keys="AuthMethod.user_id",
                back_populates="user",
                primaryjoin=f"and_(User.id==AuthMethod.user_id, AuthMethod.auth_method=='{cls.get_name()}')",
            ),
        )
        for row in cls.fields:
            setattr(
                User,
                row,
                relationship(
                    "AuthMethod",
                    foreign_keys="AuthMethod.user_id",
                    back_populates="user",
                    uselist=False,
                    primaryjoin=f"and_(User.id==AuthMethod.user_id,"
                                f" AuthMethod.auth_method=='{cls.get_name()}',AuthMethod.param=='{row}')",
                ),
            )

    @staticmethod
    @abstractmethod
    async def register(**kwargs) -> object:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    async def login(**kwargs) -> Session:
        raise NotImplementedError()
