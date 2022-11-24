import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod, User


url = "/email/registration"


def test_invalid_email(client: TestClient):
    body1 = {
        "email": f"notEmailForSure",
        "password": "string"
    }
    body2 = {
        "email": f"EmailForSure{datetime.datetime.utcnow()}@mail.gtg",
        "password": ""
    }
    body3 = {
        "email": f"EmailForSure{datetime.datetime.utcnow()}@mail.gtg",
        "password": "&%@#$@322îïíīįì3@##EFWed}efvef{}{}{}[èéêëēėę'"
    }
    body4 = {
        "email": f"EmailFor+ _Sur{datetime.datetime.utcnow()}e@mail.gtg",
        "password": "string2222"
    }
    body5 = {
        "email": f"Email For Sure {datetime.datetime.utcnow()} @ mail. gtg",
        "password": "string"
    }
    body6 = {
        "email": f"roman@dyakov.space\nContent-Type: text/html; charset=utf-8;\n\nАхаха,лох<!---",
        "password": "string"
    }
    response = client.post(url, json=body1)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    response = client.post(url, json=body3)
    assert response.status_code == status.HTTP_201_CREATED
    response = client.post(url, json=body4)
    assert response.status_code == status.HTTP_201_CREATED
    response = client.post(url, json=body5)
    assert response.status_code == status.HTTP_201_CREATED
    response = client.post(url, json=body6)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_main_scenario(client: TestClient, dbsession: Session):
    time = datetime.datetime.utcnow()
    body1 = {
        "email": f"user{time}@example.com",
        "password": "string"
    }
    response = client.post(url, json=body1)
    assert response.status_code == status.HTTP_201_CREATED
    body2 = {
        "email": f"UsEr{time}@example.com",
        "password": "string"
    }
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_200_OK
    db_user: AuthMethod = dbsession.query(AuthMethod).filter(AuthMethod.value == body1['email'],
                                                             AuthMethod.param == 'email').one()
    token = dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id,
                                               AuthMethod.param == "confirmation_token",
                                               AuthMethod.auth_method == "email").one()
    response = client.get(f"/email/approve?token={token.value}")
    response = client.post(url, json=body2)
    assert response.status_code == status.HTTP_409_CONFLICT
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == db_user.user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == db_user.user_id).one())
    dbsession.flush()


def test_repeated_registration_case(client: TestClient, dbsession: Session):
    body = {
        "email": f"user{datetime.datetime.utcnow()}@example.com",
        "password": "string"
    }
    response = client.post(url, json=body)
    assert response.status_code == status.HTTP_201_CREATED
    db_user: AuthMethod = dbsession.query(AuthMethod).filter(AuthMethod.value == body['email'],
                                                           AuthMethod.param == 'email').one()
    user_id = db_user.user_id
    prev_token = (dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                                   AuthMethod.param == 'confirmation_token',
                                                   )).one().value
    response2 = client.post(url, json=body)
    assert response2.status_code == status.HTTP_200_OK

    tokens = dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id,
                                               AuthMethod.param == 'confirmation_token',
                                               ).all()

    curr_token = tokens[-1].value
    assert curr_token != prev_token
    from_prev_token = client.get(f'/email/approve?token={prev_token}')
    assert from_prev_token.status_code == status.HTTP_403_FORBIDDEN
    from_curr_token = client.get(f'/email/approve?token={curr_token}')
    assert from_curr_token.status_code == status.HTTP_200_OK
    for row in dbsession.query(AuthMethod).filter(AuthMethod.user_id == user_id).all():
        dbsession.delete(row)
    dbsession.delete(dbsession.query(User).filter(User.id == user_id).one())
    dbsession.flush()
