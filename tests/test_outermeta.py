from unittest.mock import Mock, patch

import pytest

from auth_backend.auth_method import OuterAuthMeta
from auth_backend.models.db import AuthMethod


class Test(OuterAuthMeta):
    loginable = True

    @classmethod
    async def _is_outer_user_exists(cls, username):
        return True

    @classmethod
    async def _update_outer_user_password(cls, username, password):
        print(username, password)

    @classmethod
    async def is_active(cls):
        return False


@pytest.fixture
def mock_test():
    is_active_patch = patch.object(Test, "is_active", return_value=True)
    is_active_patch.start()
    is_user_exists_patch = patch.object(Test, "_is_outer_user_exists")
    is_user_exists_mock = is_user_exists_patch.start()
    update_user_password_patch = patch.object(Test, "_update_outer_user_password")
    update_user_password_mock = update_user_password_patch.start()
    yield {
        "is_user_exists": is_user_exists_mock,
        "update_user_password": update_user_password_mock,
    }
    is_user_exists_patch.stop()
    update_user_password_patch.stop()
    is_active_patch.stop()


@pytest.mark.asyncio
async def test_outer_deleted_notprovided(mock_test: dict[str, Mock]):
    """Пользователь удаляет аккаунт твой фф"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = None
    mock_test["is_user_exists"].return_value = False

    await Test.on_user_update(None, {"user_id": 1})

    mock_test["is_user_exists"].assert_not_called()
    mock_test["update_user_password"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_exists(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, привязанный аккаунт существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = AuthMethod(param="username", value="test_user")
    mock_test["is_user_exists"].return_value = True

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}}, {"user_id": 1})

    mock_test["is_user_exists"].assert_called_once_with("test_user")
    mock_test["update_user_password"].assert_called_once_with("test_user", "new_password")

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_notexists(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, привязанный аккаунт не существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = AuthMethod(param="username", value="test_user")
    mock_test["is_user_exists"].return_value = False

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}}, {"user_id": 1})

    mock_test["is_user_exists"].assert_called_once_with("test_user")
    mock_test["update_user_password"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_not_linked(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, нет привязанного аккаунта"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = None
    mock_test["is_user_exists"].return_value = False

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}})

    mock_test["is_user_exists"].assert_not_called()
    mock_test["update_user_password"].assert_not_called()

    uname_patch.stop()
