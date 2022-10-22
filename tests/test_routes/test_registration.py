from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod
from auth_backend.models.base import Base


class TestRegistration:
    @staticmethod
    def get_url():
        return "/email/registration"

    @staticmethod
    def delete_test_users(email: str, dbsession: Session):
        db_users = dbsession.query(AuthMethod).filter(AuthMethod.value == email).all()
        to_delete = []
        for db_user in db_users:
            to_delete.extend(dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all())
        for v in to_delete:
            dbsession.delete(v)

    def test_invalid_email(self, client: TestClient):
        body = {
            "email": "notEmailForSure",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_main_scenario(self, client: TestClient, dbsession):
        body = {
            "email": "user@example.com",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_200_OK
        self.delete_test_users(body['email'], dbsession)

    def test_repeated_registration_case(self, client: TestClient, dbsession: Session):
        body = {
            "email": "some@example.com",
            "password": "string"
        }
        response = client.post(self.get_url(), json=body)
        assert response.status_code == status.HTTP_201_CREATED
        db_user: AuthMethod = dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'],
                                                                 AuthMethod.param == 'email').one()
        user_id = db_user.user_id
        prev_token = (dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                                         AuthMethod.param == 'confirmation_token',
                                                         )).one().value
        response2 = client.post(self.get_url(), json=body)
        assert response2.status_code == status.HTTP_200_OK

        tokens = (dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                                     AuthMethod.param == 'confirmation_token',
                                                     )).all()

        curr_token = tokens[-1].value
        assert curr_token != prev_token
        from_prev_token = client.get(f'/email/approve?token={prev_token}')
        assert from_prev_token.status_code == status.HTTP_403_FORBIDDEN
        from_curr_token = client.get(f'/email/approve?token={curr_token}')
        assert from_curr_token.status_code == status.HTTP_200_OK
        self.delete_test_users(body['email'], dbsession)
