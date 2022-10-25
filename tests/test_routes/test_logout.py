
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
                                                          AuthMethod.param == "token",
                                                          AuthMethod.auth_method == "email").one()
        response = client.get(f"/email/approve?token={auth_token}")
        assert response.status_code == status.HTTP_200_OK
        response = client.post("/email/login", json=body)
        assert response.status_code == status.HTTP_200_OK
        token1 = response.json()['token']
        token2 = migrated_session.query(UserSession).filter(UserSession.token == auth_token).one()
        assert token1 == token2
        response = client.post(f"{self.get_url()}?token={auth_token}")
        assert response.status_code == status.HTTP_200_OK
        expire_date = migrated_session.query(UserSession).filter(UserSession.token == auth_token).one().expires
        assert expire_date.expired
