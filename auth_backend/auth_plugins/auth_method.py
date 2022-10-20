from __future__ import annotations
import re
from abc import abstractmethod, ABCMeta
from fastapi import APIRouter
from fastapi_sqlalchemy import db
from .models.base import Session
from auth_backend.models.db import UserSession
from datetime import datetime
from auth_backend.exceptions import AuthFailed

AUTH_METHODS: dict[str, type[AuthMethodMeta]] = {}


class AuthMethodMeta(metaclass=ABCMeta):
    FIELDS: list[str]
    router: APIRouter
    prefix: str
    tags: list[str] = []

    @classmethod
    def get_name(cls) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    def __init__(self):
        self.prefix = f"/{AuthMethodMeta.get_name()}"
        self.router = APIRouter()
        self.router.add_api_route("/registration", self.registrate, methods=["POST"])
        self.router.add_api_route("/login", self.login, methods=["POST"], response_model=Session)
        self.router.add_api_route("/logout", self.logout, methods=["POST"], response_model=None)

    @classmethod
    def __init_subclass__(cls, **kwargs):
        AUTH_METHODS[cls.__name__] = cls

    @staticmethod
    @abstractmethod
    async def registrate(**kwargs) -> object:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    async def login(**kwargs) -> Session:
        raise NotImplementedError

    @staticmethod
    async def logout(token: str) -> None:
        session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
        if not session:
            raise AuthFailed(error="Session not found")
        if session.expired:
            raise AuthFailed(error="Session expired, log in system again")
        session.expires = datetime.utcnow()
        db.session.flush()






