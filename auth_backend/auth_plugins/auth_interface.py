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

    @abstractmethod
    def register(self, session: ORMSession, **kwargs) -> Session | None:
        raise NotImplementedError()

    @abstractmethod
    def login(self, session: ORMSession, **kwargs) -> Session | None:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def change_params(token: str, session: ORMSession, **kwargs) -> None:
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
        def f(obj: AuthInterface | AuthInterface.Prop):
            attrs = []
            for attr_name in dir(obj):
                attr = getattr(obj, attr_name)
                if not isinstance(attr, AuthInterface.Prop):
                    continue
                attrs.extend(f(attr))
                if not attr in attrs:
                    attrs.append(attr)
            return attrs
        attrs = f(self)
        for attr in attrs:
            if not isinstance(attr, AuthInterface.Prop):
                continue
            # attr.name = attr.__
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
