import logging

import google_auth_oauthlib.flow
from google.oauth2 import id_token
from fastapi import Depends
from fastapi_sqlalchemy import db
from pydantic import BaseModel, Json
from google.auth.transport import requests

from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import Settings
from auth_backend.utils.security import UnionAuth

from .auth_method import OauthMeta


logger = logging.getLogger(__name__)
auth = UnionAuth(auto_error=False)


class GoogleSettings(Settings):
    GOOGLE_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/google'
    GOOGLE_SCOPES: list[str] = ['openid', 'https://www.googleapis.com/auth/userinfo.profile']
    GOOGLE_CREDENTIALS: Json


class GoogleAuth(OauthMeta):
    """Вход в приложение по аккаунту гугл
    """
    prefix = '/google'
    tags = ['Google']
    fields = ["code", "scope"]
    settings = GoogleSettings()

    class OauthResponseSchema(BaseModel):
        code: str
        scope: str | None
        state: str | None
        prompt: str | None
        authuser: str | None

    def __init__(self):
        super().__init__()

    @classmethod
    async def _register(
        cls,
        user_inp: OauthResponseSchema,
        user_session: UserSession | None = Depends(auth),
    ):
        """Создает аккаунт или привязывает существующий

        Если передана активная сессия пользователя, то привязывает аккаунт Google к аккаунту в
        активной сессии. Иначе, создает новый пользователь и делает Google первым методом входа.
        """
        flow = await cls._default_flow()
        credentials = flow.fetch_token(code=user_inp.code)
        request = requests.Request()
        guser_id = id_token.verify_oauth2_token(
            credentials.get("id_token"),
            request,
            cls.settings.GOOGLE_CREDENTIALS['web']['client_id']
        )


        if user_session is None:
            user = await cls._create_user()
        else:
            user = user_session.user

        await cls._register_auth_method(guser_id, user, db_session=db.session)

        return

    @classmethod
    async def _login(cls, user_inp: OauthResponseSchema):
        """Вход в пользователя с помощью аккаунта Google

        Производит вход, если находит пользователя по Google client_id. Если аккаунт не найден,
        создает его.
        """
        flow = await cls._default_flow()
        credentials = flow.fetch_token(**user_inp.dict(exclude_unset=True))
        request = requests.Request()
        guser_id = id_token.verify_oauth2_token(
            credentials.get("id_token"),
            request,
            cls.settings.GOOGLE_CREDENTIALS['web']['client_id']
        )

        auth_method: AuthMethod = (
            AuthMethod.query(session=db.session)
            .filter(
                AuthMethod.param == "unique_google_id",
                AuthMethod.value == guser_id['sub'],
                AuthMethod.auth_method == cls.get_name(),
            )
            .one_or_none()
        )

        if auth_method is None:
            user = await cls._create_user(db_session=db.session)
            await cls._register_auth_method(guser_id, user, db_session=db.session)
        else:
            user = auth_method.user

        return await cls._create_session(user, db_session=db.session)

    @classmethod
    async def _redirect_url(cls):
        return OauthMeta.UrlSchema(url=cls.settings.GOOGLE_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
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
            scopes=cls.settings.GOOGLE_SCOPES
        )
        flow.redirect_uri = cls.settings.GOOGLE_REDIRECT_URL
        return flow

    @classmethod
    async def _register_auth_method(cls, guser_id, user: User, *, db_session):
        """Регистрация нового пользователя или нового AuthMethod"""
        AuthMethod.create(
            user_id=user.id,
            auth_method=cls.get_name(),
            param='unique_google_id',
            value=guser_id['sub'],
            session=db_session,
        )
