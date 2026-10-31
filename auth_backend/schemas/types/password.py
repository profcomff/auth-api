import string
from typing import Any

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema

from auth_backend.settings import get_settings

settings = get_settings()

PASSWORD_ALLOWED_CHARACTERS = string.ascii_letters + string.digits + string.punctuation
PASSWORD_REQUIREMENTS = (
    f"Password must be {settings.PASSWORD_MIN_LENGTH}-{settings.PASSWORD_MAX_LENGTH} characters long and contain only "
    "ASCII letters, digits and punctuation. Spaces and non-ASCII characters are not allowed."
)


def validate_password(value: str) -> str:
    """Validate a newly created password according to the Auth API password policy."""
    if len(value) < settings.PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
    elif len(value) > settings.PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password must be at most {settings.PASSWORD_MAX_LENGTH} characters long")
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
        allowed_character_class = "".join(
            f"\\{character}" if character in "\\-]^" else character for character in PASSWORD_ALLOWED_CHARACTERS
        )
        field_schema.update(
            type="string",
            format="password",
            minLength=settings.PASSWORD_MIN_LENGTH,
            maxLength=settings.PASSWORD_MAX_LENGTH,
            pattern=f"^[{allowed_character_class}]+$",
            description=PASSWORD_REQUIREMENTS,
        )
        return field_schema
