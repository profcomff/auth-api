import pytest
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from fastapi.testclient import TestClient
import auth_backend.auth_plugins.email
from auth_backend.routes.base import app
from auth_backend.settings import get_settings
from sqlalchemy_utils import create_database, database_exists
from auth_backend.models.base import Base
from unittest.mock import Mock


@pytest.fixture(scope='session')
def client(session):
    auth_backend.auth_plugins.email.send_confirmation_email = Mock(return_value=None)
    client = TestClient(app)
    yield client


@pytest.fixture(scope='session')
def postgres() -> str:
    settings = get_settings()
    tmp_name = f"{__name__}_pytest"
    settings.DB_DSN.replace(settings.DB_DSN.split('/')[-1], tmp_name)
    tmp_url = settings.DB_DSN
    if not database_exists(tmp_url):
        create_database(tmp_url)
    yield tmp_url


@pytest.fixture(scope='session')
def engine(postgres):
    return create_engine(postgres)


@pytest.fixture(scope='session')
def session_factory(engine):
    return sessionmaker(engine, autocommit=True)


@pytest.fixture(scope='session')
def session(session_factory):
    with session_factory() as session:
        yield session


@pytest.fixture(scope='session')
def migrated_session(session, engine):
    Base.metadata.create_all(engine)
    yield session
    Base.metadata.drop_all(engine)
