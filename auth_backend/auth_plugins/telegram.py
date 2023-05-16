import hashlib
import hmac
import logging
from urllib.parse import quote, unquote

import jwt
from fastapi import Depends
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Field

from auth_backend.auth_plugins.auth_method import MethodMeta, OauthMeta, Session
from auth_backend.exceptions import AlreadyExists, OauthAuthFailed
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)


class TelegramSettings(Settings):
    TELEGRAM_REDIRECT_URL: str = "https://app.test.profcomff.com/auth"
    TELEGRAM_BOT_TOKEN: str | None


class TelegramAuthParams(MethodMeta):
    __auth_method__ = "TelegramAuth"
    __fields__ = frozenset(("user_id",))
    __required_fields__ = frozenset(("user_id",))

    user_id: AuthMethod = None


class TelegramAuth(OauthMeta):
    prefix = '/telegram'
    tags = ['Telegram']

    fields = TelegramAuthParams
    settings = TelegramSettings()

    class OauthResponseSchema(BaseModel):
        id_token: str | None = Field(help="Telegram JWT token identifier")
        id: str | None
        first_name: str | None
        last_name: str | None
        username: str | None
        photo_url: str | None
        auth_date: str | None
        hash: str | None
        scopes: list[Scope] | None
        session_name: str | None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        telegram_user_id = None
        userinfo = None

        if user_inp.id_token is None:
            userinfo = cls._check(user_inp)
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
        await cls._register_auth_method('user_id', telegram_user_id, user, db_session=db.session)

        return await cls._create_session(user, user_inp.scopes, db_session=db.session, session_name=session_name)

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema) -> Session:
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
            raise OauthAuthFailed('No users found for Telegram account', id_token)
        return await cls._create_session(user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name)

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
            raise OauthAuthFailed('Invalid user data from Telegram')
