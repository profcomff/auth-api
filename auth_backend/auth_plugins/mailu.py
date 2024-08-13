import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method.outer import ConnectionIssue, OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class MailuOuterAuthSettings(Settings):
    MAILU_AUTH_BASE_URL: AnyUrl | None = None
    MAILU_AUTH_API_KEY: str | None = None


class MailuOuterAuth(OuterAuthMeta):
    prefix = '/mailu'
    settings = MailuOuterAuthSettings()
    loginable = False

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя на сервере Mailu"""
        logger.debug("_is_outer_user_exists class=%s started", cls.get_name())
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.MAILU_AUTH_BASE_URL).removesuffix('/') + '/api/v1/user/' + username,
                headers={"Authorization": cls.settings.MAILU_AUTH_API_KEY},
            ) as response:
                if not response.ok:
                    raise ConnectionIssue(response.text)
                res: dict[str] = await response.json()
                return res.get('email') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль на сервере Mailu"""
        logger.debug("_update_outer_user_password class=%s started", cls.get_name())
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                str(cls.settings.MAILU_AUTH_BASE_URL).removesuffix('/') + '/api/v1/user/' + username,
                headers={"Authorization": cls.settings.MAILU_AUTH_API_KEY},
                json={'raw_password': password},
            ) as response:
                if not response.ok:
                    raise ConnectionIssue(response.text)
                res: dict[str] = response.ok
                logger.debug("_update_outer_user_password class=%s response %s", cls.get_name(), str(response.status))
        if res:
            logger.info("User %s updated in Mailu", username)
        else:
            logger.error("User %s can't be updated in Mailu. Error: %s", username, res)
