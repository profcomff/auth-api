import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette import status

from auth_backend.models import AuthMethod, User
from auth_backend.models.db import Group, UserSession, UserGroup
from auth_backend.routes.base import app
from auth_backend.settings import get_settings


@pytest.fixture
def client():
    patcher1 = patch("auth_backend.auth_plugins.email.send_confirmation_email")
    patcher2 = patch("auth_backend.auth_plugins.email.send_change_password_confirmation")
    patcher3 = patch("auth_backend.auth_plugins.email.send_changes_password_notification")
    patcher4 = patch("auth_backend.auth_plugins.email.send_reset_email")
    patcher5 = patch("auth_backend.utils.security.UnionAuth.__call__")
    patcher1.start()
    patcher2.start()
    patcher3.start()
    patcher4.start()
    patcher5.start()
    patcher1.return_value = None
    patcher2.return_value = None
    patcher3.return_value = None
    patcher4.return_value = None
    patcher5.return_value = UserSession(**{
        "id": 0,
        "user_id": 0,
        "expires": datetime.datetime.now() + datetime.timedelta(days=7),
        "token": "123456",
    })
    client = TestClient(app)
    yield client
    patcher1.stop()
    patcher2.stop()
    patcher3.stop()
    patcher4.stop()
    patcher5.stop()


@pytest.fixture
def client_auth():
    patcher1 = patch("auth_backend.auth_plugins.email.send_confirmation_email")
    patcher2 = patch("auth_backend.auth_plugins.email.send_change_password_confirmation")
    patcher3 = patch("auth_backend.auth_plugins.email.send_changes_password_notification")
    patcher4 = patch("auth_backend.auth_plugins.email.send_reset_email")
    patcher1.start()
    patcher2.start()
    patcher3.start()
    patcher4.start()
    patcher1.return_value = None
    patcher2.return_value = None
    patcher3.return_value = None
    patcher4.return_value = None
    client = TestClient(app)
    yield client
    patcher1.stop()
    patcher2.stop()
    patcher3.stop()
    patcher4.stop()


@pytest.fixture(scope='session')
def dbsession():
    settings = get_settings()
    engine = create_engine(settings.DB_DSN)
    TestingSessionLocal = sessionmaker(bind=engine)
    return TestingSessionLocal()


@pytest.fixture()
def user_id(client_auth: TestClient, dbsession):
    time = datetime.datetime.utcnow()
    body = {"email": f"user{time}@example.com", "password": "string"}
    client_auth.post("/email/registration", json=body)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'], AuthMethod.param == 'email').one()
    )
    yield db_user.user_id
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.flush()
    for row in dbsession.query(UserSession).filter(UserSession.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.flush()
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


@pytest.fixture()
def user(client_auth: TestClient, dbsession):
    url = "/email/login"
    time = datetime.datetime.utcnow()
    body = {"email": f"user{time}@example.com", "password": "string"}
    client_auth.post("/email/registration", json=body)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'], AuthMethod.param == 'email').one()
    )
    response = client_auth.post(url, json=body)
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
    response = client_auth.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.post(url, json=body)
    assert response.status_code == status.HTTP_200_OK
    yield {"user_id": db_user.user_id, "body": body, "login_json": response.json()}
    session = dbsession.query(UserSession).filter(UserSession.user_id == db_user.user_id).all()
    for row in session:
        dbsession.delete(row)
    dbsession.commit()
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


@pytest.fixture
def parent_id(client, dbsession):
    time = datetime.datetime.utcnow()
    body = {"name": f"group{time}", "parent_id": None}
    response = client.post(url="/group", json=body)
    yield response.json()["id"]
    dbsession.query(Group).get(response.json()["id"])
    dbsession.commit()


@pytest.fixture()
def group(dbsession, parent_id):
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


@pytest.fixture()
def user_factory(dbsession):
    _users = []

    def _user(client):
        dbsession.add(res := User())
        dbsession.flush()
        nonlocal _users
        _users.append(res)
        dbsession.commit()
        return res.id

    yield _user

    for row in dbsession.query(UserGroup).all():
        dbsession.delete(row)
    dbsession.flush()

    dbsession.query(Group).delete()
    dbsession.flush()

    dbsession.query(AuthMethod).delete()
    dbsession.flush()

    dbsession.query(UserSession).delete()
    dbsession.flush()

    dbsession.query(User).delete()
    dbsession.commit()
