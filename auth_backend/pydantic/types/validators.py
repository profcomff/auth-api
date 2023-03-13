import string
from typing import Any, Generator

from pydantic.validators import str_validator, AnyCallable

CallableGenerator = Generator[AnyCallable, None, None]


class Scope(str):
    @classmethod
    def __modify_schema__(cls, field_schema: dict[str, Any]) -> None:
        field_schema.update(type='string', format='scope')

    @classmethod
    def __get_validators__(cls) -> CallableGenerator:
        yield str_validator
        yield cls.validate

    @classmethod
    def validate(cls, val: str) -> str:
        if not val:
            raise ValueError
        val = str(val).strip()
        if val[0] == "." or val[-1] == ".":
            raise ValueError
        if len(set(val) - set(string.ascii_letters + ".")) > 0:
            raise ValueError
        return val

    __weakref__ = property(lambda self: object(), lambda self, v: None, lambda self: None)
