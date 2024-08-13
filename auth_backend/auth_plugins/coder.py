import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method.outer import ConnectionIssue, OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class CoderOuterAuthSettings(Settings):
    CODER_AUTH_BASE_URL: AnyUrl | None = None
    CODER_AUTH_ADMIN_TOKEN: str | None = None


class CoderOuterAuth(OuterAuthMeta):
    prefix = '/coder'
    settings = CoderOuterAuthSettings()
    loginable = False

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя в Coder"""
        logger.debug("_is_outer_user_exists class=%s started", cls.get_name())
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.CODER_AUTH_BASE_URL).removesuffix('/') + '/api/v2/users/' + username,
                headers={'Coder-Session-Token': cls.settings.CODER_AUTH_ADMIN_TOKEN, 'Accept': 'application/json'},
            ) as response:
                if not response.ok:
                    raise ConnectionIssue(response.text)
                res: dict[str] = await response.json()
                return res.get('username') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в Coder"""
        logger.debug("_update_outer_user_password class=%s started", cls.get_name())
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.put(
                str(cls.settings.CODER_AUTH_BASE_URL).removesuffix('/') + '/api/v2/users/' + username + '/password',
                headers={'Coder-Session-Token': cls.settings.CODER_AUTH_ADMIN_TOKEN, 'Accept': 'application/json'},
                json={'password': password},
            ) as response:
                res: dict[str] = response.ok
                logger.debug("_update_outer_user_password class=%s response %s", cls.get_name(), str(response.status))
        if res:
            logger.info("User %s updated in Coder", username)
        else:
            logger.error("User %s can't be updated in Coder. Error: %s", username, res)
