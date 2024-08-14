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

from auth_backend.auth_method import AuthPluginMeta, OauthMeta, Session
from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)


class GithubSettings(Settings):
    GITHUB_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/github'
    GITHUB_CLIENT_ID: str | None = None
    GITHUB_CLIENT_SECRET: str | None = None


class GithubAuth(OauthMeta):
    """Вход в приложение по аккаунту GitHub"""

    prefix = '/github'
    loginable = True
    tags = ['github']
    settings = GithubSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="GitHub JWT token identifier")
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт https://github.com к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает https://github.com
        первым методом входа.
        """
        old_user = None
        new_user = {}
        payload = {
            "code": user_inp.code,
            "client_id": cls.settings.GITHUB_CLIENT_ID,
            "client_secret": cls.settings.GITHUB_CLIENT_SECRET,
            "redirect_uri": cls.settings.GITHUB_REDIRECT_URL,
        }
        github_user_id = None
        userinfo = None

        if user_inp.id_token is None:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://github.com/login/oauth/access_token',
                    json=payload,
                    headers={"Accept": "application/json"},
                ) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                if 'access_token' not in token_result:
                    raise OauthAuthFailed('Invalid credentials for github account', 'Неправильные учетные данные')
                token = token_result['access_token']

                async with session.get(
                    'https://api.github.com/user',
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                ) as response:
                    userinfo = await response.json()
                    logger.error(userinfo)
                    github_user_id = userinfo['id']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            github_user_id = userinfo['id']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', github_user_id, db_session=db.session)

        if user is not None:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
            old_user = {'user_id': user.id}
        new_user['user_id'] = user.id
        gh_id = cls.create_auth_method_param('user_id', github_user_id, user.id, db_session=db.session)
        new_user[cls.get_name()] = {"user_id": gh_id.value}
        userdata = await GithubAuth._convert_data_to_userdata_format(userinfo)
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            GithubAuth.generate_kafka_key(user.id),
            userdata,
        )
        await AuthPluginMeta.user_updated(new_user, old_user)
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
        """Вход в пользователя с помощью аккаунта https://github.com

        Производит вход, если находит пользователя по уникальному идендификатору. Если аккаунт не
        найден, возвращает ошибка.
        """
        payload = {
            "code": user_inp.code,
            "client_id": cls.settings.GITHUB_CLIENT_ID,
            "client_secret": cls.settings.GITHUB_CLIENT_SECRET,
            "redirect_uri": cls.settings.GITHUB_REDIRECT_URL,
        }
        github_user_id = None
        userinfo = None
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://github.com/login/oauth/access_token',
                json=payload,
                headers={"Accept": "application/json"},
            ) as response:
                token_result = await response.json()
                logger.debug(token_result)
            if 'access_token' not in token_result:
                raise OauthAuthFailed('Invalid credentials for github account', 'Неправильные учетные данные')
            token = token_result['access_token']

            async with session.get(
                'https://api.github.com/user',
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
            ) as response:
                userinfo = await response.json()
                logger.error(userinfo)
                github_user_id = userinfo['id']

        user = await cls._get_user('user_id', github_user_id, db_session=db.session)
        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed(
                'No users found for github account', 'Не найдено пользователей для аккаунта GitHub', id_token
            )
        userdata = await GithubAuth._convert_data_to_userdata_format(userinfo)
        background_tasks.add_task(
            get_kafka_producer().produce,
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            GithubAuth.generate_kafka_key(user.id),
            userdata,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.GITHUB_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        return OauthMeta.UrlSchema(
            url=f'https://github.com/login/oauth/authorize?client_id={cls.settings.GITHUB_CLIENT_ID}&redirect_uri={quote(cls.settings.GITHUB_REDIRECT_URL)}&scope=read:user%20user:email'
        )

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        full_name = data.get('name')
        if isinstance(full_name, str):
            full_name = full_name.strip()
        items = [
            {"category": "Личная информация", "param": "Полное имя", "value": full_name},
            {"category": "Карьера", "param": "Место работы", "value": data.get("company")},
            {"category": "Личная информация", "param": "Фото", "value": data.get("avatar_url")},
            {"category": "Контакты", "param": "Электронная почта", "value": data.get("email")},
            {"category": "Контакты", "param": "Место жительства", "value": data.get("location")},
            {"category": "Контакты", "param": "Имя пользователя GitHub", "value": data.get("login")},
        ]
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
