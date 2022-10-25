
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
        query = migrated_session.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                          AuthMethod.param == "email",
                                                          AuthMethod.value == "some@example.com").one()
        auth_token = migrated_session.query(AuthMethod).filter(AuthMethod.user_id == query.user.id,
                                                          AuthMethod.param == "confirmation_token",
                                                          AuthMethod.auth_method == "email").one()
        response = client.get(f"/email/approve?token={auth_token.value}")
        assert response.status_code == status.HTTP_200_OK
        response = client.post("/email/login", json=body)
        assert response.status_code == status.HTTP_200_OK
        token = response.json()['token']
        response = client.post(f"{self.get_url()}?token={token}", json=body)
        assert response.ok
        expire_date = migrated_session.query(UserSession).filter(UserSession.token == token).one()
        assert expire_date.expired
