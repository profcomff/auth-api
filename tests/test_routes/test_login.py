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
        db_user: AuthMethod = migrated_session.query(AuthMethod).filter(AuthMethod.value == body['email'],
                                                                        AuthMethod.param == 'email').one()
        user_id = db_user.user_id
        token = (migrated_session.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                                                AuthMethod.param == 'confirmation_token',
                                                                )).one().value
        response = client.post(self.get_url(), json=token)
        assert response.status_code == status.HTTP_200_OK
        response2 = client.post("/email/registration", json=body)
        assert response2.status_code == status.HTTP_400_BAD_REQUEST
        expire_date = migrated_session.query(UserSession).filter(UserSession.token == token).one().expires
        assert expire_date < datetime.utcnow() + timedelta(seconds=1)
