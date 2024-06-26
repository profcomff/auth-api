import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method import OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class AirflowOuterAuthSettings(Settings):
    AIRFLOW_AUTH_BASE_URL: AnyUrl
    AIRFLOW_AUTH_ADMIN_USERNAME: str
    AIRFLOW_AUTH_ADMIN_PASSWORD: str


class AirflowOuterAuth(OuterAuthMeta):
    prefix = '/airflow'
    settings = AirflowOuterAuthSettings()

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя в Airflow"""
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.AIRFLOW_AUTH_BASE_URL).removesuffix('/') + '/auth/fab/v1/users/' + username,
                auth=(cls.settings.AIRFLOW_AUTH_ADMIN_USERNAME, cls.settings.AIRFLOW_AUTH_ADMIN_PASSWORD),
            ) as response:
                res: dict[str] = await response.json()
                return res.get('username') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в Airflow"""
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                str(cls.settings.AIRFLOW_AUTH_BASE_URL).removesuffix('/') + '/auth/fab/v1/users' + username,
                auth=(cls.settings.AIRFLOW_AUTH_ADMIN_USERNAME, cls.settings.AIRFLOW_AUTH_ADMIN_PASSWORD),
                json={'password': password},
            ) as response:
                res: dict[str] = response.ok
        if res:
            logger.info("User %s updated in Airflow", username)
        else:
            logger.error("User %s can't be updated in Airflow. Error: %s", username, res)
