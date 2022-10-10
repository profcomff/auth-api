from __future__ import annotations
from abc import ABCMeta
from dataclasses import dataclass
from typing import Callable
from sqlalchemy.orm import Session as ORMSession
from auth_backend.models import Session

AUTH_METHODS: dict[str, type(AuthInterface)] = {}


def add_method(method: Callable) -> Callable:
    def wrapped(*args, **kwargs):
        AUTH_METHODS.append(method.__name__)
        return method(*args, **kwargs)

    return wrapped


class AuthInterface(metaclass=ABCMeta):
    """
    Parameters:
        auth_params which auth type need: like email, hashed_password and salt
    """

    def register(self, session: ORMSession, **kwargs) -> Session | None:
        raise NotImplementedError()

    def login(self, session: ORMSession, **kwargs) -> Session | None:
        raise NotImplementedError()

    @dataclass
    class Prop:
        name: str
        datatype: type
        value: object

        def __init__(self, datatype):
            self.name = None
            self.datatype = datatype

        def set_value(self, value, **kwargs) -> datatype:
            if not isinstance(value, self.datatype):
                raise TypeError(f"Expected {self.datatype}, but got {value} with type {type(value)}")
            self.value = value
            return value

    def __init__(self, **kwargs):
        self.cols = []
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if not isinstance(attr, AuthInterface.Prop):
                continue
            attr.name = attr_name
            setattr(self, attr_name, attr.set_value(kwargs.get(attr_name)))
            self.cols += [attr]

    @classmethod
    def __init_subclass__(cls):
        AUTH_METHODS[cls.__name__] = cls

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            + ", ".join([f"{attr.name}=\"{getattr(self, attr.name)}\"" for attr in self.cols])
            + ")"
        )

    @property
    def columns(self) -> list:
        return self.cols
