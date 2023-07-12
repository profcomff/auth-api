import string
from typing import Any

from pydantic._internal import _schema_generation_shared
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema


class Scope:
    """
    Класс для валидации строки скоупа
    Скоуп должен быть строкой
    Скоуп должен быть не пустой строкой
    Скоуп не может начинаться с точки или заканчиваться ей
    Скоуп должен состоять только из букв, точек и подчеркиваний
    """

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
    ) -> core_schema.CoreSchema:
        return core_schema.general_after_validator_function(cls._validate, core_schema.str_schema())

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: _schema_generation_shared.GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = handler(core_schema)
        field_schema.update(type='string', format='scope')
        return field_schema

    @classmethod
    def _validate(cls, __input_value: str, _: core_schema.ValidationInfo) -> str:
        if __input_value == "":
            raise ValueError("Empty string are not allowed")
        __input_value = str(__input_value).strip().lower()
        if __input_value[0] == "." or __input_value[-1] == ".":
            raise ValueError("Dot can not be leading or closing")
        if len(set(__input_value) - set(string.ascii_lowercase + "._")) > 0:
            raise ValueError("Only letters, dot and underscore allowed")
        return __input_value
