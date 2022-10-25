import pytest
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod, UserSession
from datetime import datetime, timedelta

class TestLogin:
    @staticmethod
    def get_url():
        return "/email/login"

    def test_invalid_email(self, client: TestClient):
        body = {
            "email": "some_string",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_main_scenario(self, client: TestClient, migrated_session: Session):
        body = {
            "email": "some@example.com",
            "password": "string"
        }
        client.post("/email/registration", json=body)
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        query = migrated_session.query(AuthMethod).filter(AuthMethod.auth_method == "email", AuthMethod.param == "email", AuthMethod.value == "some@example.com").one()
        token = migrated_session.query(AuthMethod).filter(AuthMethod.user_id == query.user.id, AuthMethod.param == "token", AuthMethod.auth_method =="email").one()
        response = client.get(f"/email/approve?token={token}")
        assert response.status_code == status.HTTP_200_OK
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_200_OK


    @pytest.mark.parametrize(
        "email, password",
        [
            pytest.param(
                "wrong@example.com", "string", id='incorrect_email'
            ),
            pytest.param(
                "some@example.com", "strong", id='incorrect_password'
            ),
            pytest.param(
                "wrong@example.com", "strong", id='incorrect email and password'
            )
        ]
    )
    def test_incorrect_data(self, client: TestClient, migrated_session: Session, email, password):
        body = {
            "email": "some@example.com",
            "password": "string"
        }
        client.post("/email/registration", json=body)
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        query = migrated_session.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                          AuthMethod.param == "email",
                                                          AuthMethod.value == "some@example.com").one()
        token = migrated_session.query(AuthMethod).filter(AuthMethod.user_id == query.user.id,
                                                          AuthMethod.param == "token",
                                                          AuthMethod.auth_method == "email").one()
        response = client.get(f"/email/approve?token={token}")
        assert response.status_code == status.HTTP_200_OK
        client.post(self.get_url(), json=body)
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_403_FORBIDDEN
