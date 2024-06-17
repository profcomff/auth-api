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
from auth_backend.utils.string import concantenate_strings


logger = logging.getLogger(__name__)


class YandexSettings(Settings):
    YANDEX_REDIRECT_URL: str = "https://app.test.profcomff.com/auth"
    YANDEX_CLIENT_ID: str | None = None
    YANDEX_CLIENT_SECRET: str | None = None
    YANDEX_WHITELIST_DOMAINS: list[str] | None = None
    YANDEX_BLACKLIST_DOMAINS: list[str] | None = ['my.msu.ru']


class YandexAuth(OauthMeta):
    prefix = '/yandex'
    tags = ['Yandex']
    settings = YandexSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        id_token: str | None = Field(default=None, help="Yandex JWT token identifier")
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

        Если передана активная сессия пользователя, то привязывает аккаунт Yandex к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает Yandex
        первым методом входа.
        """
        old_user = None
        new_user = {}
        header = {"content-type": "application/x-www-form-urlencoded"}
        payload = {
            "grant_type": "authorization_code",
            "code": user_inp.code,
            "client_id": cls.settings.YANDEX_CLIENT_ID,
            "client_secret": cls.settings.YANDEX_CLIENT_SECRET,
        }
        userinfo = None
        yandex_user_id = None
        if user_inp.id_token is None:
            async with aiohttp.ClientSession(headers=header) as session:
                async with session.post("https://oauth.yandex.ru/token", data=payload) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                    if 'access_token' not in token_result:
                        raise OauthAuthFailed('Invalid credentials for Yandex account', 'Неправильные учетные данные')
                    token = token_result['access_token']

                get_headers = {"Authorization": f"OAuth {token}"}
                get_payload = {"format": "json"}
                async with session.get(
                    "https://login.yandex.ru/info?", headers=get_headers, data=get_payload
                ) as response:
                    userinfo = await response.json()
                    logger.debug(userinfo)
                    yandex_user_id = userinfo['id']
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            yandex_user_id = userinfo['id']
            logger.debug(yandex_user_id)

        user = await cls._get_user('user_id', yandex_user_id, db_session=db.session)
        if user:
            raise AlreadyExists(User, user.id)

        # Проверяем email на blacklist/whitelist
        email: str = userinfo['default_email']
        assert isinstance(email, str), "Почта не строка WTF"
        _, domain = email.split('@', 2)
        if cls.settings.YANDEX_WHITELIST_DOMAINS is not None and domain not in cls.settings.YANDEX_WHITELIST_DOMAINS:
            raise OauthAuthFailed(
                f'Yandex account must be {cls.settings.YANDEX_WHITELIST_DOMAINS}, got {domain}',
                f'Аккаунт Яндекс должен быть из {cls.settings.YANDEX_WHITELIST_DOMAINS}, получено {domain}',
                status_code=422,
            )
        if cls.settings.YANDEX_BLACKLIST_DOMAINS is not None and domain in cls.settings.YANDEX_BLACKLIST_DOMAINS:
            raise OauthAuthFailed(
                f'Yandex account must be not {cls.settings.YANDEX_BLACKLIST_DOMAINS}, got {domain}',
                f'Аккаунт Яндекс должен быть не из {cls.settings.YANDEX_BLACKLIST_DOMAINS}, получено {domain}',
                status_code=422,
            )

        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
            old_user = {'user_id': user.id}
        new_user["user_id"] = user.id
        ya_id = await cls._register_auth_method('user_id', yandex_user_id, user, db_session=db.session)
        new_user[cls.get_name()]["user_id"] = ya_id.value
        userdata = await YandexAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            YandexAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        await AuthPluginMeta.user_updated(new_user, old_user)
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
        """Вход в пользователя с помощью аккаунта Yandex
        Производит вход, если находит пользователя по уникаотному идендификатору. Если аккаунт не
        найден, возвращает ошибка.
        """
        header = {"content-type": "application/x-www-form-urlencoded"}
        payload = {
            "grant_type": "authorization_code",
            "code": user_inp.code,
            "client_id": cls.settings.YANDEX_CLIENT_ID,
            "client_secret": cls.settings.YANDEX_CLIENT_SECRET,
        }
        userinfo = None
        yandex_user_id = None
        async with aiohttp.ClientSession(headers=header) as session:
            async with session.post("https://oauth.yandex.ru/token", data=payload) as response:
                token_result = await response.json()
                logger.debug(token_result)
            if 'access_token' not in token_result:
                raise OauthAuthFailed('Invalid credentials for Yandex account', 'Неправильные учетные данные')
            token = token_result['access_token']

            get_headers = {"Authorization": f"OAuth {token}"}
            get_payload = {"format": "json"}
            async with session.get("https://login.yandex.ru/info?", headers=get_headers, data=get_payload) as response:
                userinfo = await response.json()
                logger.debug(userinfo)
                yandex_user_id = userinfo['id']

        user = await cls._get_user('user_id', yandex_user_id, db_session=db.session)

        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed(
                'No users found for Yandex account', 'Не найдено пользователей для аккаунт Яндекс', id_token
            )
        userdata = await YandexAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            YandexAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""

        return OauthMeta.UrlSchema(url=cls.settings.YANDEX_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""

        return OauthMeta.UrlSchema(
            url=f"https://oauth.yandex.ru/authorize?response_type=code&client_id={cls.settings.YANDEX_CLIENT_ID}&redirect_uri={quote(cls.settings.YANDEX_REDIRECT_URL)}&force_confirm=true"
        )

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        if (sex := data.get("sex")) is not None:
            sex = sex.replace('female', 'женский').replace('male', 'мужской')
        first_name, last_name = '', ''
        if 'first_name' in data.keys() and data['first_name'] is not None:
            first_name = data['first_name']
        if 'last_name' in data.keys() and data['last_name'] is not None:
            last_name = data['last_name']
        full_name = concantenate_strings([first_name, last_name])
        if not full_name:
            full_name = None
        items = [
            {"category": "Личная информация", "param": "Полное имя", "value": full_name},
            {"category": "Контакты", "param": "Электронная почта", "value": data.get("default_email")},
            {
                "category": "Контакты",
                "param": "Номер телефона",
                "value": data.get("default_phone", {}).get("number"),
            },
            {
                "category": "Личная информация",
                "param": "Дата рождения",
                "value": None if data.get("birthday") else data.get("birthday"),
            },
            {"category": "Личная информация", "param": "Пол", "value": sex},
        ]
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
