import pytest
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod


url = "/email/reset/password/"


@pytest.mark.skip()
def test_unprocessable_jsons_no_token(client: TestClient, dbsession: Session, user_id: int):
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                               AuthMethod.param == "confirmation_token",
                                               AuthMethod.auth_method == "email").one()
    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}/request")
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                     AuthMethod.param == "reset_token", AuthMethod.user_id == user_id).one()
    assert reset_token

    response = client.post(f"{url}{user_id}", json={"reset_token": reset_token, "new_password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}", json={"reset_token": "", "new_password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}", json={"reset_token": "", "new_password": "changedstring3"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.skip()
def test_unprocessable_jsons_with_token(client: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client.post(f"{url}{user_id}/request", json={"token": auth_token, "password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", json={"token": "", "password": ""})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", json={"token": "", "password": "string"})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client.post(f"{url}{user_id}/request", json={"token": auth_token, "password": "string"})
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.skip()
def test_no_token(client: TestClient, dbsession: Session, user_id: str):
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                               AuthMethod.param == "confirmation_token",
                                               AuthMethod.auth_method == "email").one()
    response = client.post(f"{url}{user_id}/request")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}/request")
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email", AuthMethod.param == "reset_token", AuthMethod.user_id == user_id).one()
    assert reset_token

    response = client.post(f"{url}{user_id}", json={"reset_token": reset_token, "password": "changedstring"})
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}", json={"reset_token": reset_token, "password": "changedstring2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.skip()
def test_with_token(client: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client.post(f"{url}{user_id}/request", json={"token": auth_token, "password": "wrong"})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client.post(f"{url}{user_id}/request", json={"token": auth_token, "password": "string"})
    assert response.status_code == status.HTTP_200_OK
    reset_token = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                     AuthMethod.param == "reset_token", AuthMethod.user_id == user_id).one()
    assert reset_token

    response = client.post(f"{url}{user_id}", json={"reset_token": reset_token, "password": "changedstring"})
    assert response.status_code == status.HTTP_200_OK

    response = client.post(f"{url}{user_id}", json={"reset_token": reset_token, "password": "changedstring2"})
    assert response.status_code == status.HTTP_403_FORBIDDEN






