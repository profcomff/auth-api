from datetime import datetime
import google.oauth2.credentials
import google_auth_oauthlib.flow
from fastapi import BackgroundTasks, Depends
from pydantic import BaseModel, BaseSettings, Json

from auth_backend.models.db import UserSession
from auth_backend.utils.security import UnionAuth

from .auth_method import OauthMeta, Session


auth = UnionAuth(auto_error=False)


class GoogleSettings(BaseSettings):
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
        scope: str
        state: str
        prompt: str | None
        authuser: str | None

    def __init__(self):
        super().__init__()

    @staticmethod
    async def _register(user_inp: OauthResponseSchema, background_tasks: BackgroundTasks, user_session: UserSession = Depends(auth)):
        return user_inp

    @staticmethod
    async def _login(user_inp: OauthResponseSchema):
        return Session(token='123', expires=datetime.now(), id=1, user_id=123)

    @classmethod
    async def _redirect_url(cls):
        return OauthMeta.UrlSchema(url=cls.settings.GOOGLE_REDIRECT_URL)

    @classmethod
    async def _auth_url(cls):
        # Docs: https://developers.google.com/identity/protocols/oauth2/web-server#python_1
        flow = google_auth_oauthlib.flow.Flow.from_client_config(
            cls.settings.GOOGLE_CREDENTIALS,
            scopes=cls.settings.GOOGLE_SCOPES
        )
        flow.redirect_uri = cls.settings.GOOGLE_REDIRECT_URL
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
        )
        return OauthMeta.UrlSchema(url=authorization_url)
