import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method import OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class CoderOuterAuthSettings(Settings):
    CODER_BASE_URL: AnyUrl
    CODER_ADMIN_TOKEN: str


class CoderOuterAuth(OuterAuthMeta):
    prefix = '/coder'
    settings = CoderOuterAuthSettings()

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя в Coder"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.CODER_BASE_URL).removesuffix('/') + '/api/v2/users/' + username,
                headers={'Coder-Session-Token': cls.settings.CODER_ADMIN_TOKEN},
            ) as response:
                res: dict[str] = await response.json()
                return res.get('username') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в Coder"""
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.put(
                str(cls.settings.CODER_BASE_URL).removesuffix('/') + '/api/v2/users/' + username + '/password',
                headers={'Coder-Session-Token': cls.settings.CODER_ADMIN_TOKEN},
                json={'password': password},
            ) as response:
                res: dict[str] = response.ok
        if res:
            logger.info("User %s updated in Coder", username)
        else:
            logger.error("User %s can't be updated in Coder. Error: %s", username, res)
