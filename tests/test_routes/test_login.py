import datetime

from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod, User


url = "/email/login"


def test_invalid_email(client: TestClient):
    body = {
        "email": "some_string",
        "password": "string"
    }
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_main_scenario(client: TestClient, dbsession: Session):
    time = datetime.datetime.utcnow()
    body = {
        "email": f"user{time}@example.com",
        "password": "string"
    }
    client.post("/email/registration", json=body)
    db_user: AuthMethod = dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'],
                                                             AuthMethod.param == 'email').one()
    id = db_user.user_id
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    query = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email", AuthMethod.param == "email", AuthMethod.value == body["email"]).one()
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == query.user.id, AuthMethod.param == "confirmation_token", AuthMethod.auth_method =="email").one()
    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_200_OK
    body_with_uppercase = {
        "email": f"User{time}@example.com",
        "password": "string"
    }
    response = client.post(url, json=body_with_uppercase)
    assert response.status_code == status.HTTP_200_OK
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == id).one())
    dbsession.flush()


def test_incorrect_data(client: TestClient, dbsession: Session):
    body1 = {
        "email": f"user{datetime.datetime.utcnow()}@example.com",
        "password": "string"
    }
    body2 = {
        "email": "wrong@example.com",
        "password": "string"
    }
    body3 = {
        "email": "some@example.com",
        "password": "strong"
    }
    body4 = {
        "email": "wrong@example.com",
        "password": "strong"
    }
    response = client.post("/email/registration", json=body1)
    db_user: AuthMethod = dbsession.query(AuthMethod).filter(AuthMethod.value == body1['email'],
                                                             AuthMethod.param == 'email').one()
    id = db_user.user_id
    response = client.post(url, json=body1)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body3)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    response = client.post(url, json=body4)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    query = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                      AuthMethod.param == "email",
                                                      AuthMethod.value == body1["email"]).one()
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == query.user.id,
                                                      AuthMethod.param == "confirmation_token",
                                                      AuthMethod.auth_method == "email").one()
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
