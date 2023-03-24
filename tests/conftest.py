import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette import status
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models.db import Group, UserGroup, User, GroupScope
from auth_backend.routes.base import app
from auth_backend.settings import get_settings
from auth_backend.models.db import AuthMethod, UserSession, Scope, UserSessionScope

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
    patcher5.return_value = UserSession(
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

@pytest.fixture()
def user_scopes(dbsession, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    dbsession.add(scope1 := Scope(name="auth.scope.create", creator_id=user_id))
    dbsession.add(scope2 := Scope(name="auth.scope.read", creator_id=user_id))
    dbsession.add(scope3 := Scope(name="auth.scope.delete", creator_id=user_id))
    dbsession.add(scope4 := Scope(name="auth.scope.update", creator_id=user_id))
    dbsession.add(scope5 := Scope(name="auth.user.delete", creator_id=user_id))
    dbsession.add(scope6 := Scope(name="auth.user.update", creator_id=user_id))
    dbsession.add(scope7 := Scope(name="auth.user.read", creator_id=user_id))
    dbsession.add(scope8 := Scope(name="auth.group.create", creator_id=user_id))
    dbsession.add(scope9 := Scope(name="auth.group.read", creator_id=user_id))
    dbsession.add(scope10 := Scope(name="auth.group.delete", creator_id=user_id))
    dbsession.add(scope11 := Scope(name="auth.group.update", creator_id=user_id))
    token_ = random_string()
    dbsession.add(user_session := UserSession(user_id=user_id, token=token_))
    dbsession.flush()
    dbsession.add(user_scope1 := UserSessionScope(scope_id=scope1.id, user_session_id=user_session.id))
    dbsession.add(user_scope2 := UserSessionScope(scope_id=scope3.id, user_session_id=user_session.id))
    dbsession.add(user_scope3 := UserSessionScope(scope_id=scope2.id, user_session_id=user_session.id))
    dbsession.add(user_scope4 := UserSessionScope(scope_id=scope4.id, user_session_id=user_session.id))
    dbsession.add(user_scope5 := UserSessionScope(scope_id=scope5.id, user_session_id=user_session.id))
    dbsession.add(user_scope6 := UserSessionScope(scope_id=scope6.id, user_session_id=user_session.id))
    dbsession.add(user_scope7 := UserSessionScope(scope_id=scope7.id, user_session_id=user_session.id))
    dbsession.add(user_scope8 := UserSessionScope(scope_id=scope8.id, user_session_id=user_session.id))
    dbsession.add(user_scope9 := UserSessionScope(scope_id=scope9.id, user_session_id=user_session.id))
    dbsession.add(user_scope10 := UserSessionScope(scope_id=scope10.id, user_session_id=user_session.id))
    dbsession.add(user_scope11 := UserSessionScope(scope_id=scope11.id, user_session_id=user_session.id))
    dbsession.commit()
    yield token_, user
    dbsession.delete(user_scope1)
    dbsession.delete(user_scope2)
    dbsession.delete(user_scope3)
    dbsession.delete(user_scope4)
    dbsession.delete(user_scope5)
    dbsession.delete(user_scope6)
    dbsession.delete(user_scope7)
    dbsession.delete(user_scope8)
    dbsession.delete(user_scope9)
    dbsession.delete(user_scope10)
    dbsession.delete(user_scope11)
    dbsession.delete(scope1)
    dbsession.delete(scope2)
    dbsession.delete(scope3)
    dbsession.delete(scope4)
    dbsession.delete(scope5)
    dbsession.delete(scope6)
    dbsession.delete(scope7)
    dbsession.delete(scope8)
    dbsession.delete(scope9)
    dbsession.delete(scope10)
    dbsession.delete(scope11)
    dbsession.delete(user_session)
    dbsession.commit()
