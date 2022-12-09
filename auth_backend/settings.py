from functools import lru_cache

from pydantic import BaseSettings, PostgresDsn, HttpUrl


class Settings(BaseSettings):
    DB_DSN: PostgresDsn

    EMAIL: str | None
    APPLICATION_HOST: str = "localhost"
    EMAIL_PASS: str = None
    SMTP_HOST: str = 'smtp.gmail.com'
    SMTP_PORT: int = 587
    ENABLED_AUTH_METHODS: list[str] | None
    FRONTEND_HOST: HttpUrl = "https://localhost.com"

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
