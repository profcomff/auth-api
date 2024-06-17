from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from auth_backend.auth_method import OuterAuthMeta

if TYPE_CHECKING:
    from unittest.mock import _patch_default_new as patch_type


class Test(OuterAuthMeta):
    @classmethod
    async def _is_user_exists(cls, username):
        print(username)

    @classmethod
    async def _create_user(cls, username, password):
        print(username, password)

    @classmethod
    async def _delete_user(cls, username):
        print(username)

    @classmethod
    async def _update_user_password(cls, username, password):
        print(username, password)


@pytest.fixture
def mock_test():
    is_user_exists_patch = patch.object(Test, "_is_user_exists")
    is_user_exists_mock = is_user_exists_patch.start()
    create_user_patch = patch.object(Test, "_create_user")
    create_user_mock = create_user_patch.start()
    delete_user_patch = patch.object(Test, "_delete_user")
    delete_user_mock = delete_user_patch.start()
    update_user_password_patch = patch.object(Test, "_update_user_password")
    update_user_password_mock = update_user_password_patch.start()
    yield {
        "is_user_exists_mock": is_user_exists_mock,
        "create_user_mock": create_user_mock,
        "delete_user_mock": delete_user_mock,
        "update_user_password_mock": update_user_password_mock,
    }
    is_user_exists_patch.stop()
    create_user_patch.stop()
    delete_user_patch.stop()
    update_user_password_patch.stop()


@pytest.mark.asyncio
async def test_outer_deleted_notexists(mock_test: dict[str, Mock]):
    """Пользователь удаляет аккаунт твой фф, нет привязки"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = None
    mock_test["is_user_exists_mock"].return_value = False

    await Test.on_user_update(None, {"user_id": 1})

    mock_test["is_user_exists_mock"].assert_not_called()
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_not_called()
    mock_test["update_user_password_mock"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_deleted_notexists(mock_test: dict[str, Mock]):
    """Пользователь удаляет аккаунт твой фф, привязанного аккаунта не существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = "test_user"
    mock_test["is_user_exists_mock"].return_value = False

    await Test.on_user_update(None, {"user_id": 1})

    mock_test["is_user_exists_mock"].assert_called_once_with("test_user")
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_not_called()
    mock_test["update_user_password_mock"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_deleted(mock_test: dict[str, Mock]):
    """Пользователь удаляет аккаунт твой фф, привязанный аккаунт существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = "test_user"
    mock_test["is_user_exists_mock"].return_value = True

    await Test.on_user_update(None, {"user_id": 1})

    mock_test["is_user_exists_mock"].assert_called_once_with("test_user")
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_called_once_with("test_user")
    mock_test["update_user_password_mock"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_exists(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, привязанный аккаунт существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = "test_user"
    mock_test["is_user_exists_mock"].return_value = True

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}})

    mock_test["is_user_exists_mock"].assert_called_once_with("test_user")
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_not_called()
    mock_test["update_user_password_mock"].assert_called_once_with("test_user", "new_password")

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_exists(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, привязанный аккаунт не существует"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = "test_user"
    mock_test["is_user_exists_mock"].return_value = True

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}})

    mock_test["is_user_exists_mock"].assert_called_once_with("test_user")
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_not_called()
    mock_test["update_user_password_mock"].assert_called_once_with("test_user", "new_password")

    uname_patch.stop()


@pytest.mark.asyncio
async def test_outer_update_password_not_linked(mock_test: dict[str, Mock]):
    """Пользователь меняет пароль, нет привязанного аккаунта"""
    uname_patch = patch.object(OuterAuthMeta, "_OuterAuthMeta__get_username")
    uname_mock = uname_patch.start()

    uname_mock.return_value = None
    mock_test["is_user_exists_mock"].return_value = False

    await Test.on_user_update({"user_id": 1, "email": {"password": "new_password"}})

    mock_test["is_user_exists_mock"].assert_not_called()
    mock_test["create_user_mock"].assert_not_called()
    mock_test["delete_user_mock"].assert_not_called()
    mock_test["update_user_password_mock"].assert_not_called()

    uname_patch.stop()


@pytest.mark.asyncio
@pytest.mark.xfail
async def test_outer_link(mock_test: dict[str, Mock]):
    """Пользователь линкует метод"""


@pytest.mark.asyncio
@pytest.mark.xfail
async def test_outer_unlink(mock_test: dict[str, Mock]):
    """Пользователь удаляет метод"""
