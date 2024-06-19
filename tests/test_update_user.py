from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from auth_backend.auth_method import AUTH_METHODS, AuthPluginMeta


if TYPE_CHECKING:
    from unittest.mock import _patch_default_new as patch_type


@pytest.mark.asyncio
async def test_user_updated():
    patches: dict[str, 'patch_type'] = {}
    mocks: dict[str, Mock] = {}
    for auth_method, cls in AUTH_METHODS.items():
        patches[auth_method] = patch.object(cls, "on_user_update")
        mocks[auth_method] = patches[auth_method].start()

    await AuthPluginMeta.user_updated({"user_id": 123})

    for auth_method in patches:
        if AUTH_METHODS[auth_method].is_active():
            mocks[auth_method].assert_called_once()
        else:
            mocks[auth_method].assert_not_called()
        patches[auth_method].stop()
