from pydantic import BaseSettings, Json
from .google import GoogleAuth
from pydantic import BaseSettings


class PhysicsSettings(BaseSettings):
    GOOGLE_REDIRECT_URL: str = 'https://app.test.profcomff.com/auth/oauth-authorized/physics-msu'
    GOOGLE_SCOPES: list[str] = ['openid', 'https://www.googleapis.com/auth/userinfo.profile']
    GOOGLE_CREDENTIALS: Json


class PhysicsAuth(GoogleAuth):
    """Вход в приложение по почте @physics.msu.ru"""

    prefix = '/physics-msu'
    settings = PhysicsSettings()
