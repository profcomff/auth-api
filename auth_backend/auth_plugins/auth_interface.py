from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass

from sqlalchemy.orm import Session

from auth_backend.models import UserSession

AUTH_METHODS: dict[str, type(AuthInterface)] = {}


class AuthInterface(metaclass=ABCMeta):
    """
    Parameters:
        auth_params which auth type need: like email, hashed_password and salt
    """

    cols = []

    @abstractmethod
    def register(self, session: Session, **kwargs) -> UserSession | str | None:
        """
        :param session: from fastapi_sqlalchemy db.session
        :param kwargs:
        :return: Session(completed registration) or str: token to confirm smth(email fox example), None if registration failed
        """
        raise NotImplementedError()

    @abstractmethod
    def login(self, session: Session, **kwargs) -> UserSession | None:
        """

        :param session: from fastapi_sqalchemy db.session
        :param kwargs:
        :return: Session(completed registration) or None if failed
        """
        raise NotImplementedError()

    @classmethod
    def __init_subclass__(cls):
        AUTH_METHODS[cls.__name__] = cls

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join([f"{attr.param}=\"{getattr(self, attr.param)}\"" for attr in self.cols])
            + ")"
        )


    @staticmethod
    @abstractmethod
    def change_params(token: str, auth_type: type, db_session: Session, **kwargs) -> None:
        raise NotImplementedError()

    @classmethod
    def columns(cls) -> list:
        return cls.cols
