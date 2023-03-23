from pydantic import Field
from .yandex import YandexAuth, YandexAuthParams
from auth_backend.settings import Settings


class MyMsuSettings(Settings):
    YANDEX_REDIRECT_URL: str = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/my-msu',
        env='MY_MSU_REDIRECT_URL',
    )
    YANDEX_CLIENT_ID: str = Field(None, env='MY_MSU_CLIENT_ID')
    YANDEX_CLIENT_SECRET: str = Field(None, env='MY_MSU_CLIENT_SECRET')
    YANDEX_WHITELIST_DOMAINS: list[str] | None = ['my.msu.ru']
    YANDEX_BLACKLIST_DOMAINS: list[str] | None = None


class MyMsuAuthParams(YandexAuthParams):
    __auth_method__ = "MyMsuAuth"


class MyMsuAuth(YandexAuth):
    """Вход в приложение по почте @my.msu.ru"""

    prefix = '/my-msu'
    fields = MyMsuAuthParams
    settings = MyMsuSettings()
