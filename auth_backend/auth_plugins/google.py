import logging

import google_auth_oauthlib.flow
import oauthlib.oauth2.rfc6749.errors
from fastapi import Depends
from fastapi_sqlalchemy import db
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests
from google.oauth2.id_token import verify_oauth2_token
from pydantic import BaseModel, Field, Json

from auth_backend.exceptions import AlreadyExists, OauthAuthFailed, OauthCredentialsIncorrect
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth
from .auth_method import OauthMeta, Session
from sqlalchemy.orm import Session as DbSession

logger = logging.getLogger(__name__)


class GoogleSettings(Settings):
    GOOGLE_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/google'
    GOOGLE_SCOPES: list[str] = ['openid', 'https://www.googleapis.com/auth/userinfo.profile']
    GOOGLE_CREDENTIALS: Json = '{}'


class GoogleAuth(OauthMeta):
    """Вход в приложение по аккаунту гугл"""

    prefix = '/google'
    tags = ['Google']
    fields = ["code", "scope"]
    settings = GoogleSettings()

    class OauthResponseSchema(BaseModel):
        code: str | None
        state: str | None
        id_token: str | None = Field(help="Google JWT token identifier")
        scopes: list[Scope] | None

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        user_session: UserSession | None = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> Session:
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт Google к аккаунту в
        активной сессии. Иначе, создает новый пользователь и делает Google первым методом входа.
        """
        if not user_inp.id_token:
            flow = await cls._default_flow()
            try:
                credentials = flow.fetch_token(**user_inp.dict(exclude_unset=True))
            except oauthlib.oauth2.rfc6749.errors.InvalidGrantError as exc:
                raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}')
            id_token = credentials.get("id_token")
        else:
            id_token = user_inp.id_token

        try:
            guser_id = verify_oauth2_token(
                id_token,
                requests.Request(),
                cls.settings.GOOGLE_CREDENTIALS['web']['client_id'],
            )
        except GoogleAuthError as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}')
        user = await cls._get_user(guser_id, db_session=db.session)
        if user is not None:
            raise AlreadyExists(User, user.id)

        if user_session is None:
            user = await cls._create_user(db_session=db.session) if user_session is None else user_session.user
        else:
            user = user_session.user
        await cls._register_auth_method(guser_id, user, db_session=db.session)

        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema):
        """Вход в пользователя с помощью аккаунта Google

        Производит вход, если находит пользователя по Google client_id. Если аккаунт не найден,
        возвращает ошибка.
        """
        flow = await cls._default_flow()
        try:
            credentials = flow.fetch_token(**user_inp.dict(exclude_unset=True))
        except oauthlib.oauth2.rfc6749.errors.OAuth2Error as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}')
        try:
            guser_id = verify_oauth2_token(
                credentials.get("id_token"),
                requests.Request(),
                cls.settings.GOOGLE_CREDENTIALS['web']['client_id'],
            )
        except GoogleAuthError as exc:
            raise OauthCredentialsIncorrect(f'Google account response invalid: {exc}')
        user = await cls._get_user(guser_id, db_session=db.session)
        if not user:
            raise OauthAuthFailed('No users found for google account', id_token=credentials.get("id_token"))
        return await cls._create_session(user, user_inp.scopes, db_session=db.session)

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
            access_type='offline',
            include_granted_scopes='true',
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
    async def _register_auth_method(cls, guser_id, user: User, *, db_session):
        """Добавление пользователю новый AuthMethod"""
        AuthMethod.create(
            user_id=user.id,
            auth_method=cls.get_name(),
            param='unique_google_id',
            value=guser_id['sub'],
            session=db_session,
        )

    @classmethod
    async def _get_user(cls, guser_id: dict[str], *, db_session: DbSession) -> User | None:
        auth_method: AuthMethod = (
            AuthMethod.query(session=db_session)
            .filter(
                AuthMethod.param == "unique_google_id",
                AuthMethod.value == guser_id['sub'],  # An identifier for the user, unique among all Google accounts
                AuthMethod.auth_method == cls.get_name(),
            )
            .limit(1)
            .one_or_none()
        )
        if auth_method:
            return auth_method.user
