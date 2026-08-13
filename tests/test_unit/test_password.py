import string

import pytest
from pydantic import BaseModel, ValidationError

from auth_backend.schemas.types.password import (
    PASSWORD_ALLOWED_CHARACTERS,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    PASSWORD_PATTERN,
    Password,
    validate_password,
)


class PasswordModel(BaseModel):
    password: Password


def test_password_accepts_allowed_ascii_characters():
    value = "Abcd123!"
    assert validate_password(value) == value
    assert PasswordModel(password=value).password == value


def test_password_accepts_all_ascii_punctuation():
    value = string.punctuation
    assert set(value) <= set(PASSWORD_ALLOWED_CHARACTERS)
    assert PasswordModel(password=value).password == value


@pytest.mark.parametrize(
    "value",
    [
        "a" * (PASSWORD_MIN_LENGTH - 1),
        "a" * (PASSWORD_MAX_LENGTH + 1),
        "пароль123",
        "password with space",
        "password\n",
        "password\t",
    ],
)
def test_password_rejects_invalid_values(value: str):
    with pytest.raises(ValidationError):
        PasswordModel(password=value)


def test_password_json_schema_contains_frontend_requirements():
    schema = PasswordModel.model_json_schema()["properties"]["password"]
    assert schema["format"] == "password"
    assert schema["minLength"] == PASSWORD_MIN_LENGTH
    assert schema["maxLength"] == PASSWORD_MAX_LENGTH
    assert schema["pattern"] == PASSWORD_PATTERN
    assert "ASCII letters, digits and punctuation" in schema["description"]
