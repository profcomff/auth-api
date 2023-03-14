import logging
from urllib.parse import quote

import aiohttp
import jwt
from fastapi import Depends
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Field

from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth
from .auth_method import OauthMeta, Session

logger = logging.getLogger(__name__)


class VkSettings(Settings):
    VK_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/vk'
    VK_CLIENT_ID: int | None
    VK_CLIENT_SECRET: str | None


class VkAuth(OauthMeta):
    prefix = '/vk'
    tags = ['vk']
    fields = []
    settings = VkSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None
        id_token: str | None = Field(help="VK JWT token identifier")
        scopes: list[int]

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт https://vk.com к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает https://vk.com
        первым методом входа.
        """
        payload = {
            "code": user_inp.code,
            "client_id": cls.settings.VK_CLIENT_ID,
            "client_secret": cls.settings.VK_CLIENT_SECRET,
            "redirect_uri": cls.settings.VK_REDIRECT_URL,
        }
        vk_user_id = None
        userinfo = None
        if user_inp.id_token is None:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://oauth.vk.com/access_token', params=payload) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                if 'access_token' not in token_result:
                    raise OauthAuthFailed('Invalid credentials for vk account')
                token = token_result['access_token']

                async with session.get(
                    'https://api.vk.com/method/users.get?',
                    params={"v": '5.131'},
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    userinfo = await response.json()
                    logger.debug(userinfo)
                    vk_user_id = userinfo['response'][0]['id']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            vk_user_id = userinfo['response'][0]['id']
            logger.debug(userinfo)

        user = await cls._get_user(vk_user_id, db_session=db.session)

        if user:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method(vk_user_id, user, db_session=db.session)

        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema) -> Session:
        """Вход в пользователя с помощью аккаунта https://lk.msu.ru

        Производит вход, если находит пользователя по уникаотному идендификатору. Если аккаунт не
        найден, возвращает ошибка.
        """
        payload = {
            "code": user_inp.code,
            "client_id": cls.settings.VK_CLIENT_ID,
            "client_secret": cls.settings.VK_CLIENT_SECRET,
            "redirect_uri": cls.settings.VK_REDIRECT_URL,
        }
        vk_user_id = None
        userinfo = None
        async with aiohttp.ClientSession() as session:
            async with session.get('https://oauth.vk.com/access_token', params=payload) as response:
                token_result = await response.json()
                logger.debug(token_result)
            if 'access_token' not in token_result:
                raise OauthAuthFailed('Invalid credentials for VK account')
            token = token_result['access_token']

            async with session.get(
                'https://api.vk.com/method/users.get?',
                params={"v": '5.131'},
                headers={"Authorization": f"Bearer {token}"},
            ) as response:
                userinfo = await response.json()
                logger.debug(userinfo)
                vk_user_id = userinfo['response'][0]['id']

        user = await cls._get_user(vk_user_id, db_session=db.session)
        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed('No users found for vk account', id_token)
        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.VK_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        return OauthMeta.UrlSchema(
            url=f'https://oauth.vk.com/authorize?client_id={cls.settings.VK_CLIENT_ID}&redirect_uri={quote(cls.settings.VK_REDIRECT_URL)}'
        )

    @classmethod
    async def _get_user(cls, vkuser_id: str | int, *, db_session: Session) -> User | None:
        auth_method: AuthMethod = (
            AuthMethod.query(session=db_session)
            .filter(
                AuthMethod.param == "user_id",
                AuthMethod.value == str(vkuser_id),
                AuthMethod.auth_method == cls.get_name(),
            )
            .one_or_none()
        )
        if auth_method:
            return auth_method.user

    @classmethod
    async def _register_auth_method(cls, vk_user_id: str | int, user: User, *, db_session):
        """Добавление пользователю новый AuthMethod"""
        AuthMethod.create(
            user_id=user.id,
            auth_method=cls.get_name(),
            param='user_id',
            value=str(vk_user_id),
            session=db_session,
        )
