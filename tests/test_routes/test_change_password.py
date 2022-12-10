import pytest
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod

url = "/email/reset/password/"


def test_unprocessable_jsons_no_token(client: TestClient, dbsession: Session, user_id: int):
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                               AuthMethod.param == "confirmation_token",
                                               AuthMethod.auth_method == "email").one()
    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}/request", json={})
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                     AuthMethod.param == "reset_token",
                                                     AuthMethod.user_id == user_id).one()
    assert reset_token

    response = client.post(f"{url}{user_id}", headers={"reset-token": reset_token.value}, json={"new_password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}", headers={"reset-token": ""}, json={"new_password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}", headers={"reset-token": ""}, json={"new_password": "changed"})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_unprocessable_jsons_with_token(client: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client.post(f"{url}{user_id}/request", headers={"token": auth_token},
                           json={"password": "", "new_password": "changed"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", headers={"token": ""},
                           json={"password": "", "new_password": "changed"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", headers={"token": ""},
                           json={"password": body["password"], "new_password": "changed"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", headers={"token": ""},
                           json={"password": body["password"], "new_password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", headers={"token": auth_token},
                           json={"password": body["password"], "new_password": "changed"})
    assert response.status_code == status.HTTP_200_OK


def test_no_token(client: TestClient, dbsession: Session, user_id: str):
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                               AuthMethod.param == "confirmation_token",
                                               AuthMethod.auth_method == "email").one()
    response = client.post(f"{url}{user_id}/request", json={})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}/request", json={})
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                     AuthMethod.param == "reset_token",
                                                     AuthMethod.user_id == user_id).one()
    assert reset_token

    response = client.post(f"{url}{user_id}", headers={"reset-token": reset_token.value+"x"}, json={"new_password": "changedstring2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.post(f"{url}{user_id}", headers={"reset-token": reset_token.value}, json={"new_password": "changedstring2"})
    assert response.status_code == status.HTTP_200_OK


def test_with_token(client: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client.post(f"{url}{user_id}/request", headers={"token": auth_token},
                           json={"password": "wrong", "new_password": "changed"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client.post(f"{url}{user_id}/request", headers={"token": auth_token + "wrong"},
                           json={"password": body["password"], "new_password": "changed"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.post(f"{url}{user_id}/request", headers={"token": auth_token},
                           json={"password": body["password"], "new_password": "changed"})
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                     AuthMethod.param == "reset_token",
                                                     AuthMethod.user_id == user_id).one_or_none()
    assert not reset_token
