import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod


url = "/email/reset/password"


def test_unprocessable_jsons_no_token(client_auth: TestClient, dbsession: Session, user_id: int):
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token", AuthMethod.auth_method == "email"
        )
        .one()
    )
    response = client_auth.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(
        f"{url}/request",
        json={
            "email": token.user.auth_methods.email.email.value,
        },
    )
    assert response.status_code == status.HTTP_200_OK
    reset_token = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.auth_method == "email", AuthMethod.param == "reset_token", AuthMethod.user_id == user_id)
        .one()
    )
    assert reset_token

    response = client_auth.post(
        f"{url}",
        headers={"reset-token": reset_token.value},
        json={"email": token.user.auth_methods.email.email.value, "new_password": ""},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(
        f"{url}",
        headers={"reset-token": ""},
        json={"email": token.user.auth_methods.email.email.value, "new_password": ""},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(
        f"{url}",
        headers={"reset-token": ""},
        json={"email": token.user.auth_methods.email.email.value, "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_unprocessable_jsons_with_token(client_auth: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": auth_token},
        json={"email": body["email"], "password": "", "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": ""},
        json={"email": body["email"], "password": "", "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": ""},
        json={"email": body["email"], "password": body["password"], "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": ""},
        json={"email": body["email"], "password": body["password"], "new_password": ""},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": auth_token},
        json={"email": body["email"], "password": body["password"], "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_200_OK


def test_no_token(client_auth: TestClient, dbsession: Session, user_id: str):
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token", AuthMethod.auth_method == "email"
        )
        .one()
    )
    response = client_auth.post(f"{url}/request", json={"email": token.user.auth_methods.email.email.value})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(f"{url}/request", json={"email": token.user.auth_methods.email.email.value})
    assert response.status_code == status.HTTP_200_OK
    reset_token: AuthMethod = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.auth_method == "email", AuthMethod.param == "reset_token", AuthMethod.user_id == user_id)
        .one()
    )
    assert reset_token

    response = client_auth.post(
        f"{url}",
        headers={"reset-token": reset_token.value + "x"},
        json={"email": token.user.auth_methods.email.email.value, "new_password": "changedstring2"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.post(
        f"{url}",
        headers={"reset-token": reset_token.value},
        json={"email": token.user.auth_methods.email.email.value, "new_password": "changedstring2"},
    )
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(
        "/email/login",
        json={"email": reset_token.user.auth_methods.email.email.value, "password": "string", "scopes": []},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.post(
        "/email/login",
        json={"email": reset_token.user.auth_methods.email.email.value, "password": "changedstring2", "scopes": []},
    )
    assert response.status_code == status.HTTP_200_OK


def test_with_token(client_auth: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    auth_token = response["token"]

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": auth_token},
        json={"email": body["email"], "password": "wrong", "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": auth_token + "wrong"},
        json={"email": body["email"], "password": body["password"], "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.post(
        f"{url}/request",
        headers={"Authorization": auth_token},
        json={"email": body["email"], "password": body["password"], "new_password": "changed"},
    )
    assert response.status_code == status.HTTP_200_OK
    reset_token = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.auth_method == "email", AuthMethod.param == "reset_token", AuthMethod.user_id == user_id)
        .one_or_none()
    )
    assert not reset_token
    response = client_auth.post(
        "/email/login", json={"email": body["email"], "password": body["password"], "scopes": []}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.post("/email/login", json={"email": body["email"], "password": "changed", "scopes": []})
    assert response.status_code == status.HTTP_200_OK


def test_no_token_two_requests(client_auth: TestClient, dbsession: Session, user_id: str):
    token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token", AuthMethod.auth_method == "email"
        )
        .one()
    )

    response = client_auth.get(f"/email/approve?token={token.value}")
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(f"{url}/request", json={"email": token.user.auth_methods.email.email.value})
    assert response.status_code == status.HTTP_200_OK
    reset_token_1: AuthMethod = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.auth_method == "email",
            AuthMethod.param == "reset_token",
            AuthMethod.user_id == user_id,
            AuthMethod.is_deleted == False,
        )
        .one()
    )
    assert reset_token_1

    response = client_auth.post(f"{url}/request", json={"email": token.user.auth_methods.email.email.value})
    assert response.status_code == status.HTTP_200_OK
    reset_token_2: AuthMethod = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.auth_method == "email",
            AuthMethod.param == "reset_token",
            AuthMethod.user_id == user_id,
            AuthMethod.is_deleted == False,
        )
        .one()
    )
    assert reset_token_2
    assert reset_token_1 != reset_token_2
