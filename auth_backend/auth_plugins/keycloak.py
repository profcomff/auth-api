import logging
from typing import Any
from urllib.parse import quote

import aiohttp
import jwt
from event_schema.auth import UserLogin
from fastapi import Depends
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Field

from auth_backend.auth_method import AuthPluginMeta, LoginableMixin, OauthMeta, Session
from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)


class KeycloakSettings(Settings):
    KEYCLOAK_ROOT_URL: str | None = None
    KEYCLOAK_REDIRECT_URL: str | None = 'https://app.test.profcomff.com/auth/oauth-authorized/keycloak'
    KEYCLOAK_CLIENT_ID: str | None = None
    KEYCLOAK_CLIENT_SECRET: str | None = None


class KeycloakAuth(OauthMeta, LoginableMixin):
    """Вход в приложение по аккаунту Keycloak"""

    prefix = '/keycloak'
    tags = ['keycloak']
    settings = KeycloakSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="Keycloak JWT token identifier")
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий"""
        old_user = None
        new_user = {}
        keycloak_user_id = None
        userinfo = None

        if user_inp.id_token is None:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{cls.settings.KEYCLOAK_ROOT_URL}/token',
                    data={
                        "grant_type": "authorization_code",
                        "code": user_inp.code,
                        "client_id": cls.settings.KEYCLOAK_CLIENT_ID,
                        "client_secret": cls.settings.KEYCLOAK_CLIENT_SECRET,
                        "redirect_uri": cls.settings.KEYCLOAK_REDIRECT_URL,
                    },
                    headers={"Accept": "application/x-www-form-urlencoded"},
                ) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                if 'access_token' not in token_result:
                    raise OauthAuthFailed(
                        'Invalid credentials for keycloak account',
                        'Неверные данные для входа в аккаунт keycloak',
                    )
                token = token_result['access_token']

                async with session.get(
                    f'{cls.settings.KEYCLOAK_ROOT_URL}/userinfo',
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                ) as response:
                    userinfo = await response.json()
                    logger.error(userinfo)
                    keycloak_user_id = userinfo['sub']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            keycloak_user_id = userinfo['sub']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', keycloak_user_id, db_session=db.session)

        if user is not None:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
            old_user = {'user_id': user.id}
        new_user["user_id"] = user.id
        keycloak_id = cls.create_auth_method_param('user_id', keycloak_user_id, user.id, db_session=db.session)
        new_user = {cls.get_name(): {"user_id": keycloak_id.value}}
        userdata = await KeycloakAuth._convert_data_to_userdata_format(userinfo)
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            KeycloakAuth.generate_kafka_key(user.id),
            userdata,
        )
        await AuthPluginMeta.user_updated(new_user, old_user)
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
        """Вход в пользователя с помощью аккаунта Keycloak"""
        form = aiohttp.FormData()
        keycloak_user_id = None
        userinfo = None
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f'{cls.settings.KEYCLOAK_ROOT_URL}/token',
                data={
                    "grant_type": "authorization_code",
                    "code": user_inp.code,
                    "client_id": cls.settings.KEYCLOAK_CLIENT_ID,
                    "client_secret": cls.settings.KEYCLOAK_CLIENT_SECRET,
                    "redirect_uri": cls.settings.KEYCLOAK_REDIRECT_URL,
                },
                headers={"Accept": "application/x-www-form-urlencoded"},
            ) as response:
                token_result = await response.json()
                logger.debug(token_result)
            if 'access_token' not in token_result:
                raise OauthAuthFailed(
                    'Invalid credentials for keycloak account',
                    'Неверные данные для входа в аккаунт keycloak',
                )
            token = token_result['access_token']

            async with session.get(
                f'{cls.settings.KEYCLOAK_ROOT_URL}/userinfo',
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            ) as response:
                userinfo = await response.json()
                logger.error(userinfo)
                keycloak_user_id = userinfo['sub']

        user = await cls._get_user('user_id', keycloak_user_id, db_session=db.session)
        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed(
                'No users found for keycloak account',
                'Пользователь с данным аккаунтом Keycloak не найден',
                id_token,
            )
        userdata = await KeycloakAuth._convert_data_to_userdata_format(userinfo)
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            KeycloakAuth.generate_kafka_key(user.id),
            userdata,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.KEYCLOAK_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        return OauthMeta.UrlSchema(
            url=f'{cls.settings.KEYCLOAK_ROOT_URL}/auth?client_id={cls.settings.KEYCLOAK_CLIENT_ID}&redirect_uri={quote(cls.settings.KEYCLOAK_REDIRECT_URL)}&scope=openid&response_type=code'
        )

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        full_name = data.get('name')
        if isinstance(full_name, str):
            full_name = full_name.strip()
        items = []
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
