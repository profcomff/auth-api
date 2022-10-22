import pytest
from fastapi.testclient import TestClient
from auth_backend.routes import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from auth_backend.settings import get_settings
from auth_backend.models.base import Base


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def dbsession():
    settings = get_settings()
    engine = create_engine(settings.DB_DSN)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return TestingSessionLocal()
