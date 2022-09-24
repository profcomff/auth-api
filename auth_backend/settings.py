from functools import lru_cache

from pydantic import BaseSettings, PostgresDsn


class Settings(BaseSettings):
    DB_DSN: PostgresDsn

    class Config:
        """Pydantic BaseSettings config"""

        case_sensitive = True
        env_file = ".env"


@lru_cache
def get_settings():
    return Settings()
