from pydantic import Field
from .yandex import YandexAuth
from auth_backend.settings import Settings


class MyMsuSettings(Settings):
    YANDEX_REDIRECT_URL: str = Field(
        'https://app.test.profcomff.com/auth/oauth-authorized/my-msu',
        env='MY_MSU_REDIRECT_URL',
    )
    YANDEX_CLIENT_ID: str | None
    YANDEX_CLIENT_SECRET: str | None


class MyMsuAuth(YandexAuth):
    """Вход в приложение по почте @my.msu.ru"""

    prefix = '/my-msu'
    settings = MyMsuSettings()
