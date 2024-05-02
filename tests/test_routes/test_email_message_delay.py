from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.settings import get_settings


settings = get_settings()


def test_message_delay(client_auth_email_delay: TestClient, dbsession: Session):
    ip_delay = get_settings().IP_DELAY_TIME_IN_MINUTES
    email_delay = get_settings().EMAIL_DELAY_TIME_IN_MINUTES
    settings_ = get_settings()
    settings_.IP_DELAY_TIME_IN_MINUTES = 1
    settings_.EMAIL_DELAY_TIME_IN_MINUTES = 1
    for i in range(settings.IP_DELAY_COUNT):
        response = client_auth_email_delay.post(
            "/email/registration", json={"email": f"test-user@profcomff.com", "password": "string"}
        )
        assert response.status_code == status.HTTP_200_OK
    delay_response = client_auth_email_delay.post(
        "/email/registration", json={"email": f"test-user@profcomff.com", "password": "string"}
    )
    assert delay_response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    settings_.IP_DELAY_TIME_IN_MINUTES = ip_delay
    settings_.EMAIL_DELAY_TIME_IN_MINUTES = email_delay
