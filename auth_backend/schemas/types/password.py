import string
from typing import Any

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 32
PASSWORD_ALLOWED_CHARACTERS = string.ascii_letters + string.digits + string.punctuation
PASSWORD_PATTERN = r"^[\x21-\x7E]+$"
PASSWORD_REQUIREMENTS = (
    f"Password must be {PASSWORD_MIN_LENGTH}-{PASSWORD_MAX_LENGTH} characters long and contain only "
    "ASCII letters, digits and punctuation. Spaces and non-ASCII characters are not allowed."
)


def validate_password(value: str) -> str:
    """Validate a newly created password according to the Auth API password policy."""
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(value) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_LENGTH} characters long")
    if any(character not in PASSWORD_ALLOWED_CHARACTERS for character in value):
        raise ValueError(
            "Password may contain only ASCII letters, digits and punctuation; "
            "spaces and non-ASCII characters are not allowed"
        )
    return value


class Password:
    """Pydantic type for a password that is being created or replaced."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(validate_password, core_schema.str_schema())

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema_: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        field_schema = handler(core_schema_)
        field_schema.update(
            type="string",
            format="password",
            minLength=PASSWORD_MIN_LENGTH,
            maxLength=PASSWORD_MAX_LENGTH,
            pattern=PASSWORD_PATTERN,
            description=PASSWORD_REQUIREMENTS,
        )
        return field_schema
