import datetime
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette import status

import auth_backend.auth_plugins.email
from auth_backend.models import AuthMethod, User
from auth_backend.models.db import Group
from auth_backend.routes.base import app
from auth_backend.settings import get_settings


@pytest.fixture(scope='session')
def client():
    auth_backend.auth_plugins.email.send_confirmation_email = Mock(return_value=None)
    auth_backend.auth_plugins.email.send_change_password_confirmation = Mock(return_value=None)
    auth_backend.auth_plugins.email.send_changes_password_notification = Mock(return_value=None)
    auth_backend.auth_plugins.email.send_reset_email = Mock(return_value=None)
    client = TestClient(app)
    yield client


@pytest.fixture(scope='session')
def dbsession():
    settings = get_settings()
    engine = create_engine(settings.DB_DSN)
    TestingSessionLocal = sessionmaker(bind=engine)
    return TestingSessionLocal()


@pytest.fixture()
def user_id(client: TestClient, dbsession):
    time = datetime.datetime.utcnow()
    body = {"email": f"user{time}@example.com", "password": "string"}
    client.post("/email/registration", json=body)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'], AuthMethod.param == 'email').one()
    )
    yield db_user.user_id
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


@pytest.fixture()
def user(client: TestClient, dbsession):
    url = "/email/login"
    time = datetime.datetime.utcnow()
    body = {"email": f"user{time}@example.com", "password": "string"}
    client.post("/email/registration", json=body)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'], AuthMethod.param == 'email').one()
    )
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == db_user.user_id,
            AuthMethod.param == "confirmation_token",
            AuthMethod.auth_method == "email",
        )
        .one()
    )
    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_200_OK
    yield {"user_id": db_user.user_id, "body": body, "login_json": response.json()}
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


@pytest.fixture()
def group(dbsession, parent_id: int):
    _ids: list[int] = []

    def _group(client: TestClient):
        time = datetime.datetime.utcnow()
        body = {"name": f"group{time}", "parent_id": parent_id}
        response = client.post(url="/group", json=body)
        nonlocal _ids
        _ids.append(_id := response.json()["id"])
        return _id
    yield _group
    for row in _ids:
        Group.delete(row, session=dbsession)
    dbsession.commit()




