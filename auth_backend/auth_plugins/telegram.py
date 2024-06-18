import hashlib
import hmac
import logging
from typing import Any
from urllib.parse import quote, unquote

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


class TelegramSettings(Settings):
    TELEGRAM_REDIRECT_URL: str = "https://app.test.profcomff.com/auth"
    TELEGRAM_BOT_TOKEN: str | None = None


class TelegramAuth(OauthMeta):
    prefix = '/telegram'
    tags = ['Telegram']
    settings = TelegramSettings()

    class OauthResponseSchema(BaseModel):
        id_token: str | None = Field(default=None, help="Telegram JWT token identifier")
        id: str | None = None
        first_name: str | None = None
        last_name: str | None = None
        username: str | None = None
        photo_url: str | None = None
        auth_date: str | None = None
        hash: str | None = None
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        old_user = None
        new_user = {}
        telegram_user_id = None
        userinfo = None

        if user_inp.id_token is None:
            userinfo = await cls._check(user_inp)
            telegram_user_id = user_inp.id
            logger.debug(userinfo)
        else:
            userinfo = jwt.decode(user_inp.id_token, cls.settings.ENCRYPTION_KEY, algorithms=["HS256"])
            telegram_user_id = userinfo['id']
            logger.debug(userinfo)

        user = await cls._get_user('user_id', telegram_user_id, db_session=db.session)

        if user is not None:
            raise AlreadyExists(User, user.id)
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
            old_user = {'user_id': user.id}
        new_user["user_id"] = user.id
        tg_id = await cls._create_auth_method_param('user_id', telegram_user_id, user, db_session=db.session)
        new_user[cls.get_name()]["user_id"] = tg_id.value
        userdata = await TelegramAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            TelegramAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        await AuthPluginMeta.user_updated(new_user, old_user)
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks) -> Session:
        """Вход в пользователя с помощью аккаунта https://lk.msu.ru

        Производит вход, если находит пользователя по уникаотному идендификатору. Если аккаунт не
        найден, возвращает ошибка.
        """

        userinfo = await cls._check(user_inp)
        telegram_user_id = user_inp.id
        logger.debug(userinfo)

        user = await cls._get_user('user_id', telegram_user_id, db_session=db.session)

        if not user:
            id_token = jwt.encode(userinfo, cls.settings.ENCRYPTION_KEY, algorithm="HS256")
            raise OauthAuthFailed(
                'No users found for Telegram account', 'Не найдено пользователей с таким ТГ аккаунтом', id_token
            )
        userdata = await TelegramAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            TelegramAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.TELEGRAM_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""

        return OauthMeta.UrlSchema(
            url=f"https://oauth.telegram.org/auth?bot_id={cls.settings.TELEGRAM_BOT_TOKEN.split(':')[0]}&origin={quote(cls.settings.TELEGRAM_REDIRECT_URL)}&return_to={quote(cls.settings.TELEGRAM_REDIRECT_URL)}"
        )

    @classmethod
    async def _check(cls, user_inp):
        '''Проверка данных пользователя

        https://core.telegram.org/widgets/login#checking-authorization
        '''
        data_check = {
            'id': user_inp.id,
            'first_name': user_inp.first_name,
            'last_name': user_inp.last_name,
            'username': user_inp.username,
            'photo_url': user_inp.photo_url,
            'auth_date': user_inp.auth_date,
        }
        check_hash = user_inp.hash
        data_check_string = ''
        for k, v in sorted(data_check.items()):
            if v is None:
                continue
            data_check_string += f'{unquote(k)}={unquote(v)}\n'
        data_check_string = data_check_string.rstrip('\n')
        secret_key = hashlib.sha256(str.encode(cls.settings.TELEGRAM_BOT_TOKEN)).digest()
        signing = hmac.new(secret_key, msg=str.encode(data_check_string), digestmod=hashlib.sha256).hexdigest()
        if signing == check_hash:
            return data_check
        else:
            raise OauthAuthFailed('Invalid user data from Telegram', 'Неправильные учетные данные')

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
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
            {"category": "Контакты", "param": "Имя пользователя Telegram", "value": data.get("username")},
            {"category": "Личная информация", "param": "Фото", "value": data.get("photo_url")},
        ]
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
