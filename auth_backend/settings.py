from functools import lru_cache

from pydantic import BaseSettings, PostgresDsn, conint

import random

import string


class Settings(BaseSettings):
    """Application settings"""

    DB_DSN: PostgresDsn = 'postgresql://postgres@localhost:5432/postgres'
    ROOT_PATH: str = '/' + os.getenv('APP_NAME', '')

    EMAIL: str | None
    APPLICATION_HOST: str = "localhost"
    EMAIL_PASS: str | None
    SMTP_HOST: str = 'smtp.gmail.com'
    SMTP_PORT: int = 587
    ENABLED_AUTH_METHODS: list[str] | None
    TOKEN_LENGTH: conint(gt=8) = 64  # type: ignore
    SESSION_TIME_IN_DAYS: int = 30

    MAX_RETRIES: int = 10
    STOP_MAX_DELAY: int = 10000
    WAIT_MIN: int = 1000
    WAIT_MAX: int = 2000

    CORS_ALLOW_ORIGINS: list[str] = ['*']
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ['*']
    CORS_ALLOW_HEADERS: list[str] = ['*']

    ENCRYPTION_KEY: str = "".join([random.choice(string.ascii_letters) for _ in range(32)])

    class Config:
        """Pydantic BaseSettings config"""

        case_sensitive = True
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()
