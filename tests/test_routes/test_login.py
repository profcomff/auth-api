import datetime

from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod, User


url = "/email/login"


def test_invalid_email(client: TestClient):
    body = {"email": "some_string", "password": "string"}
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_main_scenario(client: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    body_with_uppercase = {"email": body["email"].replace("u", "U"), "password": "string"}
    response = client.post(url, json=body_with_uppercase)
    assert response.status_code == status.HTTP_200_OK


def test_incorrect_data(client: TestClient, dbsession: Session):
    body1 = {"email": f"user{datetime.datetime.utcnow()}@example.com", "password": "string"}
    body2 = {"email": "wrong@example.com", "password": "string"}
    body3 = {"email": "some@example.com", "password": "strong"}
    body4 = {"email": "wrong@example.com", "password": "strong"}
    client.post("/email/registration", json=body1)
    db_user: AuthMethod = (
        dbsession.query(AuthMethod).filter(AuthMethod.value == body1['email'], AuthMethod.param == 'email').one()
    )
    id = db_user.user_id
    response = client.post(url, json=body1)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body3)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body4)
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
    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client.post(url, json=body1)
    assert response.status_code == status.HTTP_200_OK
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body3)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body4)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == id).one())
    dbsession.flush()


def test_check_token(client: TestClient, user, dbsession: Session):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]

    response = client.post(f"/me", headers={"token": login["token"] + "2"})
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.post(f"/me", headers={"token": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"/logout", headers={"token": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"/me", headers={"token": login["token"]})
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_invalid_check_tokens(client: TestClient, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    response = client.post(f"/me", headers={"token": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"/me")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
