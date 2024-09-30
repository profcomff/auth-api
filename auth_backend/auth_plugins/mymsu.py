from pydantic import Field

from auth_backend.settings import Settings
from auth_backend.auth_method import LoginableMixin
from .yandex import YandexAuth


class MyMsuSettings(Settings):
    YANDEX_REDIRECT_URL: str = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/my-msu',
        validation_alias='MY_MSU_REDIRECT_URL',
    )
    YANDEX_CLIENT_ID: str | None = Field(default=None, validation_alias='MY_MSU_CLIENT_ID')
    YANDEX_CLIENT_SECRET: str | None = Field(default=None, validation_alias='MY_MSU_CLIENT_SECRET')
    YANDEX_WHITELIST_DOMAINS: list[str] | None = ['my.msu.ru']
    YANDEX_BLACKLIST_DOMAINS: list[str] | None = None


class MyMsuAuth(YandexAuth, LoginableMixin):
    """Вход в приложение по почте @my.msu.ru"""

    prefix = '/my-msu'
    settings = MyMsuSettings()
