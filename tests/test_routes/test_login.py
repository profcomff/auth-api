from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod


class TestLogin:
    url = "/email/login"

    def test_invalid_email(self, client: TestClient):
        body = {
            "email": "some_string",
            "password": "string"
        }
        response = client.post(self.url, json=body)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_main_scenario(self, client: TestClient, dbsession: Session):
        body = {
            "email": "some@example.com",
            "password": "string"
        }
        client.post("/email/registration", json=body)
        response = client.post(self.url, json=body)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        query = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email", AuthMethod.param == "email", AuthMethod.value == "some@example.com").one()
        token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == query.user.id, AuthMethod.param == "confirmation_token", AuthMethod.auth_method =="email").one()
        response = client.get(f"/email/approve?token={token.value}")
        assert response.status_code == status.HTTP_200_OK
        response = client.post(self.url, json=body)
        assert response.status_code == status.HTTP_200_OK

    def test_incorrect_data(self, client: TestClient, dbsession: Session):
        body1 = {
            "email": "some@example.com",
            "password": "string"
        }
        body2 = {
            "email": "wrong@example.com",
            "password": "string"
        }
        body3 = {
            "email": "some@example.com",
            "password": "strong"
        }
        body4 = {
            "email": "wrong@example.com",
            "password": "strong"
        }
        client.post("/email/registration", json=body1)
        response = client.post(self.url, json=body1)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response = client.post(self.url, json=body2)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response = client.post(self.url, json=body3)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response = client.post(self.url, json=body4)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        query = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                          AuthMethod.param == "email",
                                                          AuthMethod.value == "some@example.com").one()
        token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == query.user.id,
                                                          AuthMethod.param == "confirmation_token",
                                                          AuthMethod.auth_method == "email").one()
        response = client.get(f"/email/approve?token={token.value}")
        assert response.status_code == status.HTTP_200_OK
        response = client.post(self.url, json=body1)
        assert response.status_code == status.HTTP_200_OK
        response = client.post(self.url, json=body2)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response = client.post(self.url, json=body3)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        response = client.post(self.url, json=body4)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
