import pytest
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from fastapi.testclient import TestClient
from auth_backend.routes.base import app
from auth_backend.settings import get_settings
from uuid import uuid4
from tests.utils import run_downgrade, run_upgrade


@pytest.fixture()
def client(session):
    client = TestClient(app)
    yield client


@pytest.fixture()
def postgres() -> str:
    settings = get_settings()
    tmp_name = f"{uuid4().hex}_pytest"
    settings.DB_DSN.replace(settings.DB_DSN.split('/')[-1], tmp_name)
    tmp_url = settings.DB_DSN
    yield tmp_url


@pytest.fixture
def engine(postgres):
    return create_engine(postgres)


@pytest.fixture
def session_factory(engine):
    return sessionmaker(engine, autocommit=True)


@pytest.fixture
def session(session_factory):
    with session_factory() as session:
        yield session


@pytest.fixture
def migrated_session(session):
    run_upgrade()
    yield session
    run_downgrade()
