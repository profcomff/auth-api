import os
import random
import string
from functools import lru_cache
from typing import Annotated

from annotated_types import Gt
from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings"""

    DB_DSN: PostgresDsn = 'postgresql://postgres@localhost:5432/postgres'

    KAFKA_DSN: str | None = None
    KAFKA_USER_LOGIN_TOPIC_NAME: str | None = "test-user-login"
    KAFKA_TIMEOUT: int = 2
    KAFKA_LOGIN: str | None = None
    KAFKA_PASSWORD: str | None = None

    ROOT_PATH: str = '/' + os.getenv('APP_NAME', '')

    EMAIL: str | None = None
    APPLICATION_HOST: str = "localhost"
    EMAIL_PASS: str | None = None
    SMTP_HOST: str = 'smtp.gmail.com'
    SMTP_PORT: int = 587
    ENABLED_AUTH_METHODS: list[str] | None = None
    TOKEN_LENGTH: Annotated[int, Gt(8)] = 64
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

    IP_DELAY_TIME_IN_MINUTES: float = 1
    IP_DELAY_COUNT: int = 3
    EMAIL_DELAY_TIME_IN_MINUTES: float = 1
    EMAIL_DELAY_COUNT: int = 3
    model_config = SettingsConfigDict(case_sensitive=True, env_file=".env", extra='ignore')


@lru_cache
def get_settings():
    return Settings()
