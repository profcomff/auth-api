from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from auth_backend.auth_plugins.auth_method import AUTH_METHODS, AuthMethodMeta
from auth_backend.utils.auth_methods import is_method_active


if TYPE_CHECKING:
    from unittest.mock import _patch_default_new as patch_type


@pytest.mark.asyncio
async def test_user_updated():
    patches: dict[str, 'patch_type'] = {}
    mocks: dict[str, Mock] = {}
    for auth_method in AUTH_METHODS:
        patches[auth_method] = patch(f"auth_backend.auth_plugins.{auth_method}.on_user_update")
        mocks[auth_method] = patches[auth_method].start()

    await AuthMethodMeta.user_updated({"user_id": 123})

    for auth_method in patches:
        if is_method_active(AUTH_METHODS[auth_method]):
            mocks[auth_method].assert_called_once()
        else:
            mocks[auth_method].assert_not_called()
        patches[auth_method].stop()
