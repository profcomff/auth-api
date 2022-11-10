from functools import lru_cache

from pydantic import BaseSettings, PostgresDsn, HttpUrl


class Settings(BaseSettings):
    DB_DSN: PostgresDsn

    EMAIL: str | None
    HOST: HttpUrl = 'http://127.0.0.1:8000'
    EMAIL_PASS: str = None
    SMTP_HOST: str = 'smtp.gmail.com'
    SMTP_PORT: int = 587

    CORS_ALLOW_ORIGINS: list[str] = ['*']
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ['*']
    CORS_ALLOW_HEADERS: list[str] = ['*']

    class Config:
        """Pydantic BaseSettings config"""

        case_sensitive = True
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()
