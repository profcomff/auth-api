from pydantic import Field, Json

from auth_backend.auth_method import LoginableMixin
from auth_backend.settings import Settings

from .google import GoogleAuth


class PhysicsSettings(Settings):
    GOOGLE_REDIRECT_URL: str = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/physics-msu',
        validation_alias='PHYSICS_REDIRECT_URL',
    )
    GOOGLE_SCOPES: list[str] = Field(
        [
            'openid',
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ],
        validation_alias='PHYSICS_SCOPES',
    )
    GOOGLE_CREDENTIALS: Json = Field('{}', validation_alias='PHYSICS_CREDENTIALS')
    GOOGLE_WHITELIST_DOMAINS: list[str] | None = ['physics.msu.ru']
    GOOGLE_BLACKLIST_DOMAINS: list[str] | None = None


class PhysicsAuth(GoogleAuth):
    """Вход в приложение по почте @physics.msu.ru"""

    prefix = '/physics-msu'
    settings = PhysicsSettings()
