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
        reg_body = {
            "email": "some_string",
            "password": "string"
        }
        client.post(self.get_url(), json=reg_body)
        body = {
            "email": email,
            "password": password
        }
        client.post(self.get_url(), json=body)
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_403_FORBIDDEN
