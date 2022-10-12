from __future__ import annotations

from abc import ABCMeta, abstractmethod
from dataclasses import dataclass

from sqlalchemy.orm import Session as ORMSession

from auth_backend.models import Session

AUTH_METHODS: dict[str, type(AuthInterface)] = {}


class AuthInterface(metaclass=ABCMeta):
    """
    Parameters:
        auth_params which auth type need: like email, hashed_password and salt
    """

    cols = []

    @dataclass()
    class Prop:
        datatype: type
        value: datatype
        param: str

    def __init__(self):
        for row in dir(self):
            if isinstance((attr := getattr(self, row)), AuthInterface.Prop):
                self.cols += [attr]

    @abstractmethod
    def register(self, session: ORMSession, **kwargs) -> Session | None:
        raise NotImplementedError()

    @abstractmethod
    def login(self, session: ORMSession, **kwargs) -> Session | None:
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

    @abstractmethod
    @staticmethod
    def change_params(token: str, auth_type: type, db_session: ORMSession, **kwargs) -> None:
        raise NotImplementedError()

    @property
    def columns(self) -> list:
        return self.cols
