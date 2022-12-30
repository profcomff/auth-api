from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod, UserSession

url = "/email/reset/email/"


def test_main_scenario(client: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    conf_token_1 = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token")
        .one()
        .value
    )
    response = client.post(f"{url}request", json={"email": "changed@mail.com"}, headers={"token": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    conf_token_2 = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token")
        .one()
        .value
    )
    assert conf_token_2 == conf_token_1

    tmp_token = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.user_id == user_id, AuthMethod.param == "tmp_email_confirmation_token")
        .one()
        .value
    )

    assert not dbsession.query(UserSession).filter(UserSession.token == login["token"]).one().expired

    response = client.post(f"/email/login", json=body)
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"/email/login", json={"email": "changed@mail.com", "password": body["password"]})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client.get(f"{url}{user_id}?token={conf_token_1}&email=changed@mail.com")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.get(f"{url}{user_id}?token={tmp_token}&email=wrong@mail.com")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.get(f"{url}{user_id}?token={tmp_token}&email=changed@mail.com")
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"/email/login", json=body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client.post(f"/email/login", json={"email": "changed@mail.com", "password": body["password"]})
    assert response.status_code == status.HTTP_200_OK


def test_invalid_jsons(client: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]

    response = client.post(f"{url}request", json={"email": "changed@mail.com"}, headers={"token": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}request", json={"email": ""}, headers={"token": login["token"]})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}request", json={"email": ""}, headers={"token": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_expired_token(client: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    response = client.post("/logout", headers={"token": login["token"]})
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}request", json={"email": "changed@mail.com"}, headers={"token": login["token"]})
    assert response.status_code == status.HTTP_403_FORBIDDEN
