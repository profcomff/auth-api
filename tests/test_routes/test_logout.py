
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod, UserSession
from datetime import datetime, timedelta


class TestLogout:
    @staticmethod
    def get_url():
        return "/logout"

    def test_main_scenario(self, client: TestClient, migrated_session: Session):
        body = {
            "email": "some@example.com",
            "password": "string"
        }
        client.post("/email/registration", json=body)
        response = client.post("/email/login", json=body)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()['token']
        token = migrated_session.query(UserSession).filter(UserSession.token == token).one()
        response = client.post(f"{self.get_url()}?token={token}")
        assert response.status_code == status.HTTP_200_OK
        expire_date = migrated_session.query(UserSession).filter(UserSession.token == token).one().expires
        assert expire_date.expired
