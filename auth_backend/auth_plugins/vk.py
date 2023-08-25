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

from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth

from ..schemas.types.scopes import Scope
from .auth_method import MethodMeta, OauthMeta, Session


logger = logging.getLogger(__name__)


class VkSettings(Settings):
    VK_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/vk'
    VK_CLIENT_ID: int | None = None
    VK_CLIENT_SECRET: str | None = None
    VK_USERDATA: list[str] | None = [
        'bdate',
        'activities',
        'city',
        'contacts',
        'education',
        'home_town',
        'nickname',
        'sex',
        'career',
        'photo_max_orig',
    ]  # Другие данные https://dev.vk.com/ru/reference/objects/user


class VkAuthParams(MethodMeta):
    __auth_method__ = "VkAuth"
    __fields__ = frozenset(("user_id",))
    __required_fields__ = frozenset(("user_id",))

    user_id: AuthMethod = None


class VkAuth(OauthMeta):
    prefix = '/vk'
    tags = ['vk']

    fields = VkAuthParams
    settings = VkSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="VK JWT token identifier")
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
                    params={"v": '5.131', 'fields': ','.join(cls.settings.VK_USERDATA)},
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    userinfo = await response.json()
                    logger.debug(userinfo)
                    vk_user_id = userinfo['response'][0]['id']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            vk_user_id = userinfo['response'][0]['id']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', vk_user_id, db_session=db.session)

        if user:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method('user_id', vk_user_id, user, db_session=db.session)
        logger.error(userinfo.get('city'))
        userdata = VkAuth._convert_data_to_userdata_format(userinfo['response'][0])
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            VkAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
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

        user = await cls._get_user('user_id', vk_user_id, db_session=db.session)
        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed('No users found for vk account', id_token)
        userdata = VkAuth._convert_data_to_userdata_format(userinfo['response'][0])
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            VkAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

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
    def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        if sex := str(data.get('sex')) is not None:
            sex = sex.replace('1', 'женский').replace('2', 'мужской')
        items = [
            {"category": "Контакты", "param": "VK-ID", "value": data.get("nickname")},
            {"category": "Личная информация", "param": "Имя", "value": data.get("first_name")},
            {"category": "Личная информация", "param": "Фамилия", "value": data.get("last_name")},
            {"category": "Личная информация", "param": "Дата рождения", "value": data.get("bdate")},
            {"category": "Контакты", "param": "Номер телефона", "value": data.get("mobile_phone")},
            {"category": "Контакты", "param": "Домашний номер телефона", "value": data.get("home_phone")},
            {"category": "Контакты", "param": "Город", "value": data.get("city", {}).get("title")},
            {"category": "Контакты", "param": "Родной город", "value": data.get("home_town")},
            {"category": "Учёба", "param": "ВУЗ", "value": data.get("university_name")},
            {"category": "Учёба", "param": "Факультет", "value": data.get("faculty_name")},
            {"category": "Карьера", "param": "Место работы", "value": data.get("career", {}).get("company")},
            {"category": "Карьера", "param": "Расположение работы", "value": data.get("career", {}).get("city_name")},
            {"category": "Личная информация", "param": "Фото", "value": data.get("photo_max_orig")},
            {"category": "Личная информация", "param": "Пол", "value": sex},
        ]
        result = {"items": items, "source": cls.get_name()}
        return UserLogin.model_validate(result)
