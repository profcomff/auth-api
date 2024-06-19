import logging
from contextlib import contextmanager
from typing import Generator

from pydantic import PostgresDsn
from sqlalchemy import Result, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from auth_backend.auth_method import OuterAuthMeta
from auth_backend.settings import Settings


logger = logging.getLogger(__name__)


class PostgresOuterAuthSettings(Settings):
    POSTGRES_AUTH_DB_DSN: PostgresDsn = 'postgresql://postgres@localhost:5432/postgres'


class PostgresOuterAuth(OuterAuthMeta):
    prefix = '/postgres'
    settings = PostgresOuterAuthSettings()
    __sessionmaker: type[Session] | None = None

    @classmethod
    @contextmanager
    def _session(cls) -> Generator[Session, None, None]:
        if not cls.__sessionmaker:
            engine = create_engine(cls.settings.POSTGRES_AUTH_DB_DSN)
            cls.__sessionmaker = sessionmaker(engine)
        with cls.__sessionmaker as conn:
            yield conn

    @classmethod
    async def _is_outer_user_exists(cls, username: str) -> bool:
        """Проверяет наличие пользователя в Postgres"""
        with cls._session() as session:
            exists = session.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname=:username;"),
                {"username": username},
            ).scalar()  # returns 1 or None
        return bool(exists)

    @classmethod
    async def _update_outer_user_password(cls, username: str, password: str):
        """Устанавливает пользователю новый пароль в Postgres"""
        with cls._session() as session:
            res: Result = session.execute(
                text("ALTER USER :username WITH PASSWORD :password;"),
                {"username": username, "password": password},
            )
        if res.is_success:
            logger.info("User %s updated in Postgres", username)
        else:
            logger.error("User %s can't be updated in Postgres", username)
