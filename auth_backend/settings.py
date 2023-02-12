from functools import lru_cache

from pydantic import BaseSettings, PostgresDsn, conint


class Settings(BaseSettings):
    DB_DSN: PostgresDsn

    EMAIL: str | None
    APPLICATION_HOST: str = "localhost"
    EMAIL_PASS: str
    SMTP_HOST: str = 'smtp.gmail.com'
    SMTP_PORT: int = 587
    ENABLED_AUTH_METHODS: list[str] | None
    TOKEN_LENGTH: conint(gt=8) = 64  # type: ignore

    MAX_RETRIES: int = 10
    STOP_MAX_DELAY: int = 10000
    WAIT_MIN: int = 1000
    WAIT_MAX: int = 2000

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
