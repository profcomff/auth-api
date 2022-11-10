from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette import status

import auth_backend.auth_plugins.email
from auth_backend.models import AuthMethod, User
from auth_backend.routes.base import app
from auth_backend.settings import get_settings


@pytest.fixture(scope='session')
def client():
    auth_backend.auth_plugins.email.send_confirmation_email = Mock(return_value=None)
    client = TestClient(app)
    yield client


@pytest.fixture(scope='session')
def dbsession():
    settings = get_settings()
    engine = create_engine(settings.DB_DSN)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return TestingSessionLocal()
