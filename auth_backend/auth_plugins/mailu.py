import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method import OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class MailuOuterAuthSettings(Settings):
    MAILU_BASE_URL: AnyUrl
    MAILU_API_KEY: str


class MailuOuterAuth(OuterAuthMeta):
    prefix = '/airflow'
    settings = MailuOuterAuthSettings()

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя на сервере Mailu"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.MAILU_BASE_URL).removesuffix('/') + '/user/' + username,
                headers={"Authorization": cls.settings.MAILU_API_KEY},
            ) as response:
                res: dict[str] = await response.json()
                return res.get('username') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль на сервере Mailu"""
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                str(cls.settings.MAILU_BASE_URL).removesuffix('/') + '/user/' + username,
                headers={"Authorization": cls.settings.MAILU_API_KEY},
                json={'raw_password': password},
            ) as response:
                res: dict[str] = response.ok
        if res:
            logger.info("User %s updated in Mailu", username)
        else:
            logger.error("User %s can't be updated in Mailu. Error: %s", username, res)
