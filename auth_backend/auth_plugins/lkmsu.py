from datetime import datetime
import google.oauth2.credentials
import google_auth_oauthlib.flow
from fastapi import BackgroundTasks, Depends
from pydantic import BaseModel, BaseSettings, Json

from auth_backend.models.db import UserSession
from auth_backend.utils.security import UnionAuth

from .auth_method import OauthMeta, Session


auth = UnionAuth(auto_error=False)


class LkmsuSettings(BaseSettings):
    LKMSU_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/lk-msu'
    LKMSU_CREDENTIALS: Json


class LkmsuAuth(OauthMeta):
    """Вход в приложение по аккаунту гугл
    """
    prefix = '/lk-msu'
    tags = ['lk_msu']
    fields = []
    settings = LkmsuSettings()

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
        pass

    @staticmethod
    async def _login(user_inp: OauthResponseSchema):
        return Session(token='123', expires=datetime.now(), id=1, user_id=123)

    @classmethod
    async def _redirect_url(cls):
        pass

    @classmethod
    async def _auth_url(cls):
        pass
