import logging
from typing import Any

import google_auth_oauthlib.flow
import oauthlib.oauth2.rfc6749.errors
from event_schema.auth import UserLogin
from fastapi import Depends
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2.id_token import verify_oauth2_token
from pydantic import BaseModel, Field, Json

from auth_backend.auth_method.auth_method import AuthMethodMeta
from auth_backend.auth_method.oauth import OauthMeta
from auth_backend.auth_method.session import Session
from auth_backend.exceptions import AlreadyExists, OauthAuthFailed, OauthCredentialsIncorrect
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)


class GoogleSettings(Settings):
    GOOGLE_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/google'
    GOOGLE_SCOPES: list[str] = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/userinfo.email',
    ]
    GOOGLE_CREDENTIALS: Json = '{}'
    GOOGLE_WHITELIST_DOMAINS: list[str] | None = None
    GOOGLE_BLACKLIST_DOMAINS: list[str] | None = ['physics.msu.ru']


class GoogleAuth(OauthMeta):
    """Вход в приложение по аккаунту гугл"""

    prefix = '/google'
    tags = ['Google']
    settings = GoogleSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None = None
        state: str | None = None
        id_token: str | None = Field(default=None, help="Google JWT token identifier")
        scopes: list[Scope] | None = None
        session_name: str | None = None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        background_tasks: BackgroundTasks,
        user_session: UserSession | None = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт Google к аккаунту в
        активной сессии. иначе, создает новый пользователь и делает Google первым методом входа.
        """
        old_user = None
        new_user = {}
        credentials = None
        if not user_inp.id_token:
            flow = await cls._default_flow()
            try:
                credentials = flow.fetch_token(**user_inp.model_dump(exclude_unset=True))
            except oauthlib.oauth2.rfc6749.errors.InvalidGrantError as exc:
                raise OauthCredentialsIncorrect(
                    f'Google account response invalid: {exc}', 'Запрос к АПИ Гугла неуспешен'
                )
            id_token = credentials.get("id_token")
        else:
            id_token = user_inp.id_token

        try:
            userinfo = verify_oauth2_token(
                id_token,
                requests.Request(),
                cls.settings.GOOGLE_CREDENTIALS['web']['client_id'],
                clock_skew_in_seconds=1,
            )
        except GoogleAuthError as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}', 'Запрос к АПИ Гугла неуспешен')
        user = await cls._get_user('unique_google_id', userinfo['sub'], db_session=db.session)
        if user is not None:
            raise AlreadyExists(User, user.id)
        # Проверяем email на blacklist/whitelist
        email: str = userinfo['email']
        assert isinstance(email, str), "Почта не строка WTF"
        _, domain = email.split('@', 2)
        if cls.settings.GOOGLE_WHITELIST_DOMAINS is not None and domain not in cls.settings.GOOGLE_WHITELIST_DOMAINS:
            raise OauthAuthFailed(
                f'Google account must be {cls.settings.GOOGLE_WHITELIST_DOMAINS}, got {domain}',
                f'Google аккаунт должен быть из {cls.settings.GOOGLE_WHITELIST_DOMAINS}, получено: {domain}',
                status_code=422,
            )
        if cls.settings.GOOGLE_BLACKLIST_DOMAINS is not None and domain in cls.settings.GOOGLE_BLACKLIST_DOMAINS:
            raise OauthAuthFailed(
                f'Google account must be not {cls.settings.GOOGLE_BLACKLIST_DOMAINS}, got {domain}',
                f'Google аккаунт должен быть из {cls.settings.GOOGLE_BLACKLIST_DOMAINS}, получено: {domain}',
                status_code=422,
            )
        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
            old_user = {'user_id': user.id}
        new_user["user_id"] = user.id
        google_id = await cls._register_auth_method('unique_google_id', userinfo['sub'], user, db_session=db.session)
        new_user = {cls.get_name(): {"unique_google_id": google_id.value}}
        userdata = await GoogleAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            GoogleAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        await AuthMethodMeta.user_updated(new_user, old_user)
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema, background_tasks: BackgroundTasks):
        """Вход в пользователя с помощью аккаунта Google

        Производит вход, если находит пользователя по Google client_id. Если аккаунт не найден,
        возвращает ошибка.
        """
        flow = await cls._default_flow()
        try:
            credentials = flow.fetch_token(**user_inp.model_dump(exclude_unset=True))
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}', 'Запрос к АПИ Гугла неуспешен')
        try:
            userinfo = verify_oauth2_token(
                credentials.get("id_token"),
                requests.Request(),
                cls.settings.GOOGLE_CREDENTIALS['web']['client_id'],
                clock_skew_in_seconds=1,
            )
        except GoogleAuthError as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}', 'Запрос к АПИ Гугла неуспешен')
        user = await cls._get_user('unique_google_id', userinfo['sub'], db_session=db.session)
        if not user:
            raise OauthAuthFailed(
                'No users found for google account',
                'Не найдено пользователей с таким гугл аккаунтом',
                id_token=credentials.get("id_token"),
            )
        userdata = await GoogleAuth._convert_data_to_userdata_format(userinfo)
        await get_kafka_producer().produce(
            cls.settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            GoogleAuth.generate_kafka_key(user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @classmethod
    async def _redirect_url(cls):
        """URL на который происходит редирект после завершения входа на стороне провайдера"""
        return OauthMeta.UrlSchema(url=cls.settings.GOOGLE_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        """URL на который происходит редирект из приложения для авторизации на стороне провайдера"""
        # Docs: https://developers.google.com/identity/protocols/oauth2/web-server#python_1
        flow = await cls._default_flow()
        authorization_url, _ = flow.authorization_url(
            access_type='offline', include_granted_scopes='true', prompt='select_account'
        )
        return OauthMeta.UrlSchema(url=authorization_url)

    @classmethod
    async def _default_flow(cls) -> google_auth_oauthlib.flow.Flow:
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            cls.settings.GOOGLE_CREDENTIALS,
            scopes=cls.settings.GOOGLE_SCOPES,
        )
        flow.redirect_uri = cls.settings.GOOGLE_REDIRECT_URL
        return flow

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, Any]) -> UserLogin:
        full_name = data.get('name')
        if isinstance(full_name, str):
            full_name = full_name.strip()
        items = [
            {"category": "Контакты", "param": "Электронная почта", "value": data.get("email")},
            {"category": "Личная информация", "param": "Полное имя", "value": data.get("name")},
            {"category": "Личная информация", "param": "Фото", "value": data.get("picture")},
        ]
        result = {"items": items, "source": cls.get_name()}
        return cls.userdata_process_empty_strings(UserLogin.model_validate(result))
