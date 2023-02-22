import datetime

from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models.db import AuthMethod, User, UserSession, Scope, UserSessionScope, GroupScope, UserGroup, Group

url = "/email/login"


def test_invalid_email(client: TestClient):
    body = {"email": "some_string", "password": "string"}
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_main_scenario(client_auth: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    body_with_uppercase = {"email": body["email"].replace("u", "U"), "password": "string", "scopes": []}
    response = client_auth.post(url, json=body_with_uppercase)
    assert response.status_code == status.HTTP_200_OK


def test_incorrect_data(client_auth: TestClient, dbsession: Session):
    body1 = {"email": f"user{datetime.datetime.utcnow()}@example.com", "password": "string", "scopes": []}
    body2 = {"email": "wrong@example.com", "password": "string", "scopes": []}
    body3 = {"email": "some@example.com", "password": "strong", "scopes": []}
    body4 = {"email": "wrong@example.com", "password": "strong", "scopes": []}
    client_auth.post("/email/registration", json=body1)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body1['email'], AuthMethod.param == 'email').one()
    )
    id = db_user.user_id
    response = client_auth.post(url, json=body1)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client_auth.post(url, json=body2)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client_auth.post(url, json=body3)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client_auth.post(url, json=body4)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    query = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.auth_method == "email", AuthMethod.param == "email", AuthMethod.value == body1["email"])
        .one()
    )
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == query.user.id,
            AuthMethod.param == "confirmation_token",
            AuthMethod.auth_method == "email",
        )
        .one()
    )
    response = client_auth.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.post(url, json=body1)
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.post(url, json=body2)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client_auth.post(url, json=body3)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client_auth.post(url, json=body4)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == id).all():
        dbsession.delete(row)
    dbsession.flush()
    for row in dbsession.query(UserSession).filter(UserSession.user_id == id).all():
        dbsession.delete(row)
    dbsession.flush()
    dbsession.delete(dbsession.query(User).filter(User.id == id).one())
    dbsession.commit()


def test_check_token(client_auth: TestClient, user, dbsession: Session):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]

    response = client_auth.get(f"/me", headers={"Authorization": login["token"] + "2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.get(f"/me", headers={"Authorization": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(f"/logout", headers={"Authorization": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.get(f"/me", headers={"Authorization": login["token"]})
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_invalid_check_tokens(client_auth: TestClient, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    response = client_auth.get(f"/me", headers={"Authorization": ""})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.get(f"/me")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_check_me_groups(client_auth: TestClient, user, dbsession):
    user_id, body_user, login = user["user_id"], user["body"], user["login_json"]
    dbsession.add(scope1 := Scope(name="auth.group.create", creator_id=user_id))
    dbsession.flush()
    dbsession.add(scope3 := Scope(name="auth.user_group.create", creator_id=user_id))
    dbsession.flush()
    token_ = random_string()
    dbsession.add(user_session := UserSession(user_id=user_id, token=token_))
    dbsession.flush()
    dbsession.add(UserSessionScope(scope_id=scope1.id, user_session_id=user_session.id))
    dbsession.flush()
    dbsession.add(UserSessionScope(scope_id=scope3.id, user_session_id=user_session.id))
    dbsession.commit()
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    _group1 = client_auth.post(url="/group", json=body, headers={"Authorization": token_}).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1, "scopes": []}
    _group2 = client_auth.post(url="/group", json=body, headers={"Authorization": token_}).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2, "scopes": []}
    _group3 = client_auth.post(url="/group", json=body, headers={"Authorization": token_}).json()["id"]
    response = client_auth.post(f"/group/{_group3}/user", json={"user_id": user_id}, headers={"Authorization": token_})
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.get(f"/me", headers={"Authorization": login["token"]}, params={"info": "groups"})
    assert response.status_code == status.HTTP_200_OK
    assert _group3 in [row["id"] for row in response.json()["groups"]]
    assert _group2 not in [row["id"] for row in response.json()["groups"]]
    assert _group1 not in [row["id"] for row in response.json()["groups"]]
    response = client_auth.get(f"/me", headers={"Authorization": login["token"]}, params={"info": "indirect_groups"})
    assert response.status_code == status.HTTP_200_OK
    assert _group3 in [row["id"] for row in response.json()["indirect_groups"]]
    assert _group2 in [row["id"] for row in response.json()["indirect_groups"]]
    assert _group1 in [row["id"] for row in response.json()["indirect_groups"]]
    dbsession.query(UserSessionScope).delete()
    dbsession.delete(user_session)
    dbsession.query(GroupScope).delete()
    dbsession.query(UserGroup).delete()
    dbsession.query(Group).delete()
    dbsession.query(Scope).delete()
    dbsession.commit()
