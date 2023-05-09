from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from auth_backend.models import AuthMethod, User
from auth_backend.models.db import Group


def test_user_email(client: TestClient, dbsession: Session, user_factory):
    user1 = user_factory(client)
    time1 = datetime.utcnow()
    user: User = dbsession.query(User).get(user1)
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    email_user = AuthMethod(user_id=user1, param="email", auth_method="email", value="testemailx@x.xy")
    dbsession.add(email_user)
    dbsession.commit()
    resp = client.patch(f"/user/{user1}", json={"groups": [group]})
    assert resp.status_code == 200
    assert "email" not in resp.json().keys()
    dbsession.delete(email_user)
    gr = Group.get(group, session=dbsession)
    dbsession.delete(gr)
    dbsession.commit()
