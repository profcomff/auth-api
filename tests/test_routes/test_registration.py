import datetime
import random
import string

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import get_settings

url = "/email/registration"
settings = get_settings()


def test_invalid_email(client_auth: TestClient, dbsession: Session):
    body1 = {"email": "notEmailForSure", "password": "test-password"}
    body2 = {"email": f"EmailFor+ _Sur{datetime.datetime.utcnow()}e@mail.gtg", "password": "string2222"}
    body3 = {"email": f"Email For Sure {datetime.datetime.utcnow()} @ mail. gtg", "password": "test-password"}
    body4 = {
        "email": "roman@dyakov.space\nContent-Type: text/html; charset=utf-8;\n\nАхаха,лох<!---",
        "password": "test-password",
    }

    response = client_auth.post(url, json=body1)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    response = client_auth.post(url, json=body2)
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.post(url, json=body3)
    assert response.status_code == status.HTTP_200_OK
    response = client_auth.post(url, json=body4)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    ids = []
    for email in [body2["email"], body3["email"]]:
        ids.append(
            dbsession.query(AuthMethod).filter(AuthMethod.param == "email", AuthMethod.value == email).one().user_id
        )
    for user_id in ids:
        for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id).all():
            dbsession.delete(row)
        dbsession.delete(dbsession.query(User).filter(User.id == user_id).one())
    dbsession.commit()


def test_invalid_password(client_auth: TestClient):
    invalid_passwords = [
        "a" * (settings.PASSWORD_MIN_LENGTH - 1),
        "a" * (settings.PASSWORD_MAX_LENGTH + 1),
        "пароль123",
        "password with space",
        "password\n",
        "password\t",
    ]

    for index, password in enumerate(invalid_passwords):
        response = client_auth.post(
            url,
            json={"email": f"invalid-password-{index}@example.com", "password": password},
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_main_scenario(client_auth: TestClient, dbsession: Session):
    time = datetime.datetime.utcnow()
    body1 = {"email": f"user{time}@example.com", "password": "test-password"}
    response = client_auth.post(url, json=body1)
    assert response.status_code == status.HTTP_200_OK
    body2 = {"email": f"UsEr{time}@example.com", "password": "test-password"}
    response = client_auth.post(url, json=body2)
    assert response.status_code == status.HTTP_200_OK
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body1['email'], AuthMethod.param == 'email').one()
    )
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == db_user.user_id,
            AuthMethod.param == "confirmation_token",
            AuthMethod.auth_method == "email",
        )
        .one()
    )
    client_auth.get(f"/email/approve?token={token.value}")
    response = client_auth.post(url, json=body2)
    assert response.status_code == status.HTTP_409_CONFLICT
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


def test_repeated_registration_case(client_auth: TestClient, dbsession: Session):
    body = {"email": f"user{datetime.datetime.utcnow()}@example.com", "password": "test-password"}
    response = client_auth.post(url, json=body)
    assert response.status_code == status.HTTP_200_OK
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'], AuthMethod.param == 'email').one()
    )
    user_id = db_user.user_id
    prev_token = (
        (
            dbsession.query(AuthMethod).filter(
                AuthMethod.user_id == user_id,
                AuthMethod.param == 'confirmation_token',
            )
        )
        .one()
        .value
    )
    response2 = client_auth.post(url, json=body)
    assert response2.status_code == status.HTTP_200_OK

    tokens = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == user_id,
            AuthMethod.param == 'confirmation_token',
        )
        .all()
    )

    curr_token = tokens[-1].value
    assert curr_token != prev_token
    from_prev_token = client_auth.get(f'/email/approve?token={prev_token}')
    assert from_prev_token.status_code == status.HTTP_403_FORBIDDEN
    from_curr_token = client_auth.get(f'/email/approve?token={curr_token}')
    assert from_curr_token.status_code == status.HTTP_200_OK
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == user_id).one())
    dbsession.commit()


def test_user_exists(client_auth: TestClient, dbsession: Session):
    user = User.create(session=dbsession)
    _token = "".join([random.choice(string.ascii_letters) for _ in range(12)])
    session = UserSession.create(session=dbsession, user_id=user.id, token=_token)
    dbsession.commit()
    time = datetime.datetime.utcnow()
    email = f"user{time}@example.com"
    response = client_auth.post(
        url, headers={"Authorization": _token}, json={"user_id": user.id, "email": email, "password": "test-password"}
    )
    assert response.status_code == status.HTTP_200_OK
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == email, AuthMethod.param == 'email').one()
    )
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
    assert response.status_code == 200
    dbsession.delete(session)
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.commit()


def test_double_email_registration(client_auth: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    time = datetime.datetime.utcnow()
    body1 = {
        "email": body["email"],
        "password": "test-password",
        "scopes": [],
        "session_name": "name",
    }
    response = client_auth.post("/email/login", json=body1)
    token_ = response.json()['token']
    body2 = {"email": f"new{time}@email.com", "password": "random-pwd"}
    body3 = {"email": body["email"], "password": "test-password"}
    response = client_auth.post(url, headers={"Authorization": token_}, json=body2)
    assert response.status_code == status.HTTP_409_CONFLICT
    response = client_auth.post(url, headers={"Authorization": token_}, json=body3)
    assert response.status_code == status.HTTP_409_CONFLICT
