from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod
from auth_backend.settings import get_settings


settings = get_settings()


def test_oidc(client_auth: TestClient):
    response = client_auth.get("/openid/.well_known/openid_configuration")
    assert response.status_code == status.HTTP_200_OK
    assert list(response.json().keys()) == [
        "issuer",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "scopes_supported",
        "response_types_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
        "claims_supported",
        "grant_types_supported",
    ]


def test_jwks(client_auth: TestClient):
    response = client_auth.get("/openid/.well_known/jwks")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()["keys"][0]
    assert data["kty"] == "RSA"
    assert data["use"] == "sig"
    assert data["alg"] == "RS256"
    assert set(["n", "e", "kid"]) < set(data.keys())


def test_token_from_token_ok(client_auth: TestClient, dbsession: Session):
    # Подготовка к тесту
    body = {"email": f"user{datetime.utcnow()}@example.com", "password": "string", "scopes": []}
    user_response = client_auth.post("/email/registration", json=body)
    query = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.auth_method == "email", AuthMethod.param == "email", AuthMethod.value == body["email"])
        .one()
    )
    id = query.user_id
    auth_token = (
        dbsession.query(AuthMethod)
        .filter(
            AuthMethod.user_id == query.user.id,
            AuthMethod.param == "confirmation_token",
            AuthMethod.auth_method == "email",
        )
        .one()
    )
    response = client_auth.get(f"/email/approve?token={auth_token.value}")
    assert response.status_code == status.HTTP_200_OK, response.json()
    response = client_auth.post("/email/login", json=body)
    assert response.status_code == status.HTTP_200_OK, response.json()
    token = response.json()['token']

    # Сам тест
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "refresh_token",
            "client_id": "app",
            "refresh_token": token,
        },
    )
    assert response.status_code == status.HTTP_200_OK, response.json()

    data = response.json()
    assert list(data.keys()) == [
        "access_token",
        "token_type",
        "expires_in",
        "refresh_token",
    ], list(data.keys())
    assert data["token_type"] == "Bearer", data["token_type"]
    assert (  # Длительность токена отличается не более, чем на 10 секунд
        abs(data["expires_in"] - settings.SESSION_TIME_IN_DAYS * 24 * 60 * 60) < 10
    ), data["expires_in"]


def test_token_from_token_wrong(client_auth: TestClient):
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "refresh_token",
            "client_id": "app",
            "refresh_token": "123123",
        },
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN  # Wrong refresh token


def test_token_from_creds_ok(client_auth: TestClient, user):
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "client_credentials",
            "client_id": "app",
            "username": user["body"]["email"],
            "password": "string",
        },
    )
    assert response.status_code == status.HTTP_200_OK


def test_token_from_creds_wrong_pass(client_auth: TestClient):
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "client_credentials",
            "client_id": "app",
            "username": "admin@profcomff.com",
            "password": "password",
        },
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED  # Wrong pass


def test_token_from_creds_wrong_client_id(client_auth: TestClient):
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "client_credentials",
            "client_id": "not-app",
            "username": "admin@profcomff.com",
            "password": "password",
        },
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_token_from_creds_wrong_grant_type(client_auth: TestClient):
    response = client_auth.post(
        "/openid/token",
        headers={"User-Agent": "TestAgent"},
        data={
            "grant_type": "code",
            "client_id": "app",
            "username": "admin@profcomff.com",
            "password": "password",
        },
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
