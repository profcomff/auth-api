from pydantic import Json, Field
from .google import GoogleAuth
from auth_backend.settings import Settings


class PhysicsSettings(Settings):
    GOOGLE_REDIRECT_URL: str | None = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/physics-msu',
        env='PHYSICS_REDIRECT_URL'
    )
    GOOGLE_SCOPES: list[str] | None = Field(
        ['openid', 'https://www.googleapis.com/auth/userinfo.profile'],
        env='PHYSICS_SCOPES'
    )
    GOOGLE_CREDENTIALS: Json | None = Field(
        ...,
        env='PHYSICS_CREDENTIALS'
    )


class PhysicsAuth(GoogleAuth):
    """Вход в приложение по почте @physics.msu.ru"""

    prefix = '/physics-msu'
    settings = PhysicsSettings()
