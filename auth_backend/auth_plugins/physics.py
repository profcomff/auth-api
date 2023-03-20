from pydantic import Json, Field
from .google import GoogleAuth
from auth_backend.settings import Settings


class PhysicsSettings(Settings):
    GOOGLE_REDIRECT_URL: str = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/physics-msu',
        env='PHYSICS_REDIRECT_URL',
    )
    GOOGLE_SCOPES: list[str] = Field(
        [
            'openid',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ],
        env='PHYSICS_SCOPES',
    )
    GOOGLE_CREDENTIALS: Json = Field('{}', env='PHYSICS_CREDENTIALS')
    GOOGLE_WHITELIST_DOMAINS: list[str] | None = ['physics.msu.ru']
    GOOGLE_BLACKLIST_DOMAINS: list[str] | None = None


class PhysicsAuth(GoogleAuth):
    """Вход в приложение по почте @physics.msu.ru"""

    prefix = '/physics-msu'
    settings = PhysicsSettings()
