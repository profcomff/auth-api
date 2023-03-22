import logging
from urllib.parse import quote

import aiohttp
import jwt
from fastapi import Depends
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Field

from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.models.db import UserSession, AuthMethod
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth
from .auth_method import OauthMeta, Session, AuthMethodMeta

logger = logging.getLogger(__name__)


class GithubSettings(Settings):
    GITHUB_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/github'
    GITHUB_CLIENT_ID: str | None
    GITHUB_CLIENT_SECRET: str | None


class GithubAuth(OauthMeta):
    """Вход в приложение по аккаунту GitHub"""

    prefix = '/github'
    tags = ['github']

    class GithubAuth(AuthMethodMeta.MethodMeta):
        __fields__ = frozenset(("user_id",))
        __required_fields__ = frozenset(("user_id",))

        user_id: AuthMethod = None

    fields = []
    settings = GithubSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None
        id_token: str | None = Field(help="LK MSU JWT token identifier")
        scopes: list[Scope] | None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт https://github.com к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает https://github.com
        первым методом входа.
        """
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
                    raise OauthAuthFailed('Invalid credentials for github account')
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
            github_user_id = userinfo['user_id']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', github_user_id, db_session=db.session)

        if user is not None:
            raise AlreadyExists(user, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method('user_id', github_user_id, user, db_session=db.session)

        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema) -> Session:
        """Вход в пользователя с помощью аккаунта https://github.com

        Производит вход, если находит пользователя по уникаотному идендификатору. Если аккаунт не
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
                raise OauthAuthFailed('Invalid credentials for github account')
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
            raise OauthAuthFailed('No users found for lk msu account', id_token)
        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

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
