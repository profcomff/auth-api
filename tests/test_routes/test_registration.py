from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod


class TestRegistration:
    @staticmethod
    def get_url():
        return "/email/registration"

    def test_invalid_email(self, client: TestClient):
        body = {
            "email": "notEmailForSure",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_main_scenario(self, client: TestClient):
        body = {
            "email": "user@example.com",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_200_OK

    def test_repeated_registration_case(self, client: TestClient, dbsession: Session):
        body = {
            "email": "gimme_more_emails@example.com",
            "password": "very_strong"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_200_OK
        prev_tokens = set(dbsession. \
                          query(AuthMethod). \
                          filter(AuthMethod.param == "confirmation_token",
                                 AuthMethod.value == body['email'],
                                 AuthMethod.auth_method == 'email') \
                          .all())
        response2 = client.post(self.get_url(), json=body)
        assert response2.status_code == status.HTTP_200_OK
        tokens = set(dbsession. \
                     query(AuthMethod). \
                     filter(AuthMethod.param == "confirmation_token",
                            AuthMethod.value == body['email'],
                            AuthMethod.auth_method == 'email') \
                     .all())
        last_token = list((tokens - prev_tokens))[0]
        from_prev_token = client.get(f'/email/approve?token={list(tokens)[0]}')
        assert from_prev_token.status_code == status.HTTP_403_FORBIDDEN
        from_curr_token = client.get(f'/email/approve?token={last_token}')
        assert from_curr_token.status_code == status.HTTP_201_CREATED
