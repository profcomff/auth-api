import pytest
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

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

    def test_main_scenario(self, client: TestClient, dbsession: Session):
        pass
