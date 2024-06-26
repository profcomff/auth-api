import logging

import aiohttp
from pydantic import AnyUrl

from auth_backend.auth_method.outer import OuterAuthMeta, ConnectionIssue
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class AirflowOuterAuthSettings(Settings):
    AIRFLOW_AUTH_BASE_URL: AnyUrl | None = None
    AIRFLOW_AUTH_ADMIN_USERNAME: str | None = None
    AIRFLOW_AUTH_ADMIN_PASSWORD: str | None = None


class AirflowOuterAuth(OuterAuthMeta):
    prefix = '/airflow'
    settings = AirflowOuterAuthSettings()

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя в Airflow"""
        logger.debug("_is_outer_user_exists class=%s started", cls.get_name())
        async with aiohttp.ClientSession() as session:
            async with session.get(
                str(cls.settings.AIRFLOW_AUTH_BASE_URL).removesuffix('/') + '/auth/fab/v1/users/' + username,
                auth=aiohttp.BasicAuth(cls.settings.AIRFLOW_AUTH_ADMIN_USERNAME, cls.settings.AIRFLOW_AUTH_ADMIN_PASSWORD),
            ) as response:
                if not response.ok:
                    raise ConnectionIssue(response.text)
                res: dict[str] = await response.json()
                return res.get('username') == username

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в Airflow"""
        logger.debug("_update_outer_user_password class=%s started", cls.get_name())
        res = False
        async with aiohttp.ClientSession() as session:
            async with session.patch(
                str(cls.settings.AIRFLOW_AUTH_BASE_URL).removesuffix('/') + '/auth/fab/v1/users' + username,
                auth=(cls.settings.AIRFLOW_AUTH_ADMIN_USERNAME, cls.settings.AIRFLOW_AUTH_ADMIN_PASSWORD),
                json={'password': password},
            ) as response:
                res: dict[str] = response.ok
                logger.debug("_update_outer_user_password class=%s response %s", cls.get_name(), str(response.status))
        if res:
            logger.info("User %s updated in Airflow", username)
        else:
            logger.error("User %s can't be updated in Airflow. Error: %s", username, res)
