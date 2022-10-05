from abc import ABCMeta
from dataclasses import dataclass

from auth_backend.models import Session


class AuthInterface(metaclass=ABCMeta):
    """
    Parameters:
        auth_params which auth type need: like email, hashed_password and salt
    """

    def register(self) -> Session | None:
        raise NotImplementedError()

    def login(self) -> Session | None:
        raise NotImplementedError()

    def logout(self) -> None:
        raise NotImplementedError()

    def change_params(self) -> Session | None:
        raise NotImplementedError()

    def forgot_password(self) -> Session | None:
        raise NotImplementedError()

    @dataclass
    class Prop:
        name: str
        datatype: type
        value: object

        def __init__(self, datatype):
            self.name = None
            self.datatype = datatype

        def set_value(self, value):
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

    def __repr__(self):
        return (
                f"{self.__class__.__name__}(" +
                ", ".join([
                    f"{attr.name}=\"{getattr(self, attr.name)}\""
                    for attr in self.cols
                ]) +
                ")"
        )

    @property
    def columns(cls) -> list:
        return cls.cols
