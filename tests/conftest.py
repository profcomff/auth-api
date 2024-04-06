import datetime
import errno
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette import status

from auth_backend.auth_plugins import YandexAuth
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models import AuthMethod, User
from auth_backend.models.db import AuthMethod, Group, Scope, User, UserGroup, UserSession, UserSessionScope
from auth_backend.routes.base import app
from auth_backend.settings import get_settings


@pytest.fixture
def client():
    patcher1 = patch("auth_backend.auth_plugins.email.SendEmailMessage.send")
    patcher2 = patch("auth_backend.utils.security.UnionAuth.__call__")
    patcher1.start()
    patcher2.start()
    patcher1.return_value = None
    patcher2.return_value = UserSession(
        **{
            "id": 0,
            "user_id": 0,
            "expires": datetime.datetime.now() + datetime.timedelta(days=7),
            "token": "123456",
        }
    )
    client = TestClient(app)
    yield client
    patcher1.stop()
    patcher2.stop()


@pytest.fixture
def client_auth():
    patcher1 = patch("auth_backend.auth_plugins.email.SendEmailMessage.send")
    patcher1.start()
    patcher1.return_value = None
    client = TestClient(app)
    yield client
    patcher1.stop()


@pytest.fixture()
def dbsession():
    settings = get_settings()
    engine = create_engine(str(settings.DB_DSN))
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
    body = {"email": f"user{time}@example.com", "password": "string", "scopes": []}
    response = client_auth.post("/email/registration", json=body)
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
    body = {"name": f"group{time}", "parent_id": None, "scopes": []}
    response = client.post(url="/group", json=body)
    yield response.json()["id"]
    dbsession.query(Group).get(response.json()["id"])
    dbsession.commit()


@pytest.fixture()
def group(dbsession, parent_id):
    _ids: list[int] = []

    def _group(client: TestClient):
        time = datetime.datetime.utcnow()
        body = {"name": f"group{time}", "parent_id": parent_id, "scopes": []}
        response = client.post(url="/group", json=body)
        nonlocal _ids
        _ids.append(_id := response.json()["id"])
        return _id

    yield _group
    for row in _ids:
        group: Group = Group.get(row, session=dbsession)
        group.users.clear()
        group.delete(session=dbsession)
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

    dbsession.query(GroupScope).delete()
    dbsession.flush()

    dbsession.query(Scope).delete()
    dbsession.flush()

    dbsession.query(Group).delete()
    dbsession.flush()

    dbsession.query(AuthMethod).delete()
    dbsession.flush()

    dbsession.query(UserSession).delete()
    dbsession.flush()

    dbsession.query(User).delete()
    dbsession.commit()


@pytest.fixture()
def user_scopes(dbsession, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    scopes_names = [
        "auth.scope.create",
        "auth.scope.read",
        "auth.scope.delete",
        "auth.scope.update",
        "auth.user.delete",
        "auth.user.update",
        "auth.user.read",
        "auth.group.create",
        "auth.group.read",
        "auth.group.delete",
        "auth.group.update",
        "auth.session.create",
        "auth.session.update",
    ]
    scopes = []
    for i in scopes_names:
        dbsession.add(scope1 := Scope(name=i, creator_id=user_id))
        scopes.append(scope1)
    token_ = random_string()
    dbsession.add(user_session := UserSession(user_id=user_id, token=token_))
    dbsession.commit()
    user_scopes = []
    for i in scopes:
        dbsession.add(user_scope1 := UserSessionScope(scope_id=i.id, user_session_id=user_session.id))
        user_scopes.append(user_scope1)
    dbsession.flush()
    dbsession.commit()
    yield token_, user
    for i in user_scopes:
        dbsession.delete(i)
    dbsession.flush()
    for i in scopes:
        dbsession.delete(i)
    dbsession.delete(user_session)
    dbsession.commit()


@pytest.fixture()
def client_auth_email_delay():
    patcher1 = patch("auth_backend.auth_plugins.email.SendEmailMessage.email_task")
    patcher1.start()
    patcher1.return_value = None
    client = TestClient(app)
    yield client
    patcher1.stop()


@pytest.fixture()
def yandex_user(dbsession) -> User:
    email = f"{random_string()}@yandex.ru"
    if (
        AuthMethod.query(session=dbsession)
        .filter(AuthMethod.value == email, AuthMethod.auth_method == YandexAuth.get_name())
        .one_or_none()
    ):
        exit(errno.EIO)
    user = User.create(session=dbsession)
    dbsession.flush()
    user_id = AuthMethod.create(
        user_id=user.id, param="user_id", value=user.id, auth_method=YandexAuth.get_name(), session=dbsession
    )
    dbsession.add(user_id)
    dbsession.commit()
    yield user
    user.sessions.clear()
    user.groups.clear()
    dbsession.query(AuthMethod).filter(AuthMethod.user_id == user.id).delete()
    dbsession.query(User).filter(User.id == user.id).delete()
    dbsession.commit()
