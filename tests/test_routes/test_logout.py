
from starlette import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from auth_backend.models.db import AuthMethod, UserSession, User
from datetime import datetime


url = "/logout"


def test_main_scenario(client: TestClient, dbsession: Session):
    body = {
        "email": f"user{datetime.utcnow()}@example.com",
        "password": "string"
    }
    user_response = client.post("/email/registration", json=body)
    query = dbsession.query(AuthMethod).filter(AuthMethod.auth_method == "email",
                                                      AuthMethod.param == "email",
                                                      AuthMethod.value == body["email"]).one()
    id = query.user_id
    auth_token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == query.user.id,
                                                      AuthMethod.param == "confirmation_token",
                                                      AuthMethod.auth_method == "email").one()
    response = client.get(f"/email/approve?token={auth_token.value}")
    assert response.status_code == status.HTTP_200_OK
    response = client.post("/email/login", json=body)
    assert response.status_code == status.HTTP_200_OK
    token = response.json()['token']
    response = client.post(f"{url}?token={token}", json=body)
    assert response.ok
    expire_date = dbsession.query(UserSession).filter(UserSession.token == token).one()
    assert expire_date.expired
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == id).all():
       dbsession.delete(row)
    dbsession.delete(dbsession.query(UserSession).filter(UserSession.user_id == id).one())
    dbsession.delete(dbsession.query(User).filter(User.id == id).one())
    dbsession.flush()
