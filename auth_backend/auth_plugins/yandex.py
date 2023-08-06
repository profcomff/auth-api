import logging
from urllib.parse import quote

import aiohttp
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


class YandexSettings(Settings):
    YANDEX_REDIRECT_URL: str = "https://app.test.profcomff.com/auth"
    YANDEX_CLIENT_ID: str | None = None
    YANDEX_CLIENT_SECRET: str | None = None
    YANDEX_WHITELIST_DOMAINS: list[str] | None = None
    YANDEX_BLACKLIST_DOMAINS: list[str] | None = ['my.msu.ru']


class YandexAuthParams(MethodMeta):
    __auth_method__ = "YandexAuth"
    __fields__ = frozenset(("user_id",))
    __required_fields__ = frozenset(("user_id",))

    user_id: AuthMethod = None


class YandexAuth(OauthMeta):
    prefix = '/yandex'
    tags = ['Yandex']
    _source = "yandex"

    fields = YandexAuthParams
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
        user_session: UserSession = Depends(UnionAuth(auto_error=True, scopes=[], allow_none=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт Yandex к
        аккаунту в активной сессии. Иначе, создает новый пользователь и делает Yandex
        первым методом входа.
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
        if user_inp.id_token is None:
            async with aiohttp.ClientSession(headers=header) as session:
                async with session.post("https://oauth.yandex.ru/token", data=payload) as response:
                    token_result = await response.json()
                    logger.debug(token_result)
                    if 'access_token' not in token_result:
                        raise OauthAuthFailed('Invalid credentials for Yandex account')
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
                f'Yandex account must be {cls.settings.YANDEX_WHITELIST_DOMAINS}, got {domain}', status_code=422
            )
        if cls.settings.YANDEX_BLACKLIST_DOMAINS is not None and domain in cls.settings.YANDEX_BLACKLIST_DOMAINS:
            raise OauthAuthFailed(
                f'Yandex account must be not {cls.settings.YANDEX_BLACKLIST_DOMAINS}, got {domain}', status_code=422
            )

        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method('user_id', yandex_user_id, user, db_session=db.session)

        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema) -> Session:
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
                raise OauthAuthFailed('Invalid credentials for Yandex account')
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
            raise OauthAuthFailed('No users found for Yandex account', id_token)
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

    # def _convert_data_to_userdata_format(self, data: dict[str, Any]) -> UserLogin:
    #     items = []
    #     if data.get("first_name"):
    #         items.append({"category": "common", "param": "first_name", "value": data.get("first_name")})
    #     if data.get("last_name"):
    #         items.append({"category": "common", "param": "last_name", "value": data.get("last_name")})
    #     if data.get("default_email"):
    #         items.append({"category": "contacts", "param": "email", "value": data.get("default_email")})
    #     if data.get("default_phone") and data.get("default_phone").get("number"):
    #         items.append({"category": "contacts", "param": "phone", "value": data.get("default_phone").get("number")})
    #     if data.get("birthday"):
    #         items.append({"category": "common", "param": "birthday", "value": data.get("birthday")})
    #     if data.get("sex"):
    #         items.append({"category": "common", "param": "sex", "value": data.get("sex")})
    #     result = {"items": items,  "source": self._source}
    #     return UserLogin.model_validate(result)
