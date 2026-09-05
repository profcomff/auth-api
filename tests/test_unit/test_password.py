import re
import string

import pytest
from pydantic import BaseModel, ValidationError

from auth_backend.schemas.types.password import PASSWORD_ALLOWED_CHARACTERS, Password, validate_password
from auth_backend.settings import get_settings

settings = get_settings()


class PasswordModel(BaseModel):
    password: Password


def test_password_accepts_allowed_ascii_characters():
    value = "Abcd123!"
    assert validate_password(value) == value
    assert PasswordModel(password=value).password == value


@pytest.mark.parametrize("punctuation", string.punctuation)
def test_password_accepts_all_ascii_punctuation(punctuation: str):
    assert punctuation in PASSWORD_ALLOWED_CHARACTERS
    value = "a" * (settings.PASSWORD_MIN_LENGTH - 1) + punctuation
    assert validate_password(value) == value
    assert PasswordModel(password=value).password == value


@pytest.mark.parametrize(
    "value",
    [
        "a" * (settings.PASSWORD_MIN_LENGTH - 1),
        "a" * (settings.PASSWORD_MAX_LENGTH + 1),
        "пароль123",
        "password with space",
        "password\n",
        "password\t",
    ],
)
def test_password_rejects_invalid_values(value: str):
    with pytest.raises(ValidationError):
        PasswordModel(password=value)


def test_password_json_schema_matches_settings_and_allowed_characters():
    schema = PasswordModel.model_json_schema()["properties"]["password"]
    assert schema["format"] == "password"
    assert schema["minLength"] == settings.PASSWORD_MIN_LENGTH
    assert schema["maxLength"] == settings.PASSWORD_MAX_LENGTH
    assert "ASCII letters, digits and punctuation" in schema["description"]

    pattern = re.compile(schema["pattern"])
    assert pattern.fullmatch(PASSWORD_ALLOWED_CHARACTERS)
    assert not pattern.fullmatch("password with space")
    assert not pattern.fullmatch("пароль123")
