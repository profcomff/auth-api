import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod, UserSession

url = "/email/reset/email/"


def test_main_scenario(client_auth: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    conf_token_1 = (
        dbsession.query(AuthMethod)
        .filter(AuthMethod.user_id == user_id, AuthMethod.param == "confirmation_token")
        .one()
        .value
    )
    tmp_email = f"changed{datetime.datetime.utcnow()}@mail.com"
    response = client_auth.post(f"{url}request", json={"email": tmp_email}, headers={"Authorization": login["token"]})
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

    response = client_auth.post(f"/email/login", json=body)
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(f"/email/login", json={"email": tmp_email, "password": body["password"], "scopes": []})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.get(f"{url}?token={conf_token_1}")
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.get(f"{url}?token={tmp_token}")
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(f"/email/login", json=body)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = client_auth.post(f"/email/login", json={"email": tmp_email, "password": body["password"], "scopes": []})
    assert response.status_code == status.HTTP_200_OK


def test_invalid_jsons(client_auth: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]

    response = client_auth.post(f"{url}request", json={"email": "changed@mail.com"}, headers={"Authorization": ""})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = client_auth.post(f"{url}request", json={"email": ""}, headers={"Authorization": login["token"]})
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    response = client_auth.post(f"{url}request", json={"email": ""}, headers={"Authorization": ""})
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_expired_token(client_auth: TestClient, dbsession: Session, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    response = client_auth.post("/logout", headers={"Authorization": login['token']})
    assert response.status_code == status.HTTP_200_OK

    response = client_auth.post(
        f"{url}request", json={"email": "changed@mail.com"}, headers={"Authorization": login["token"]}
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN
