from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from auth_backend.models import AuthMethod, User
from auth_backend.models.db import Group, GroupScope, UserGroup


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


def test_delete_user(client: TestClient, dbsession: Session, user_factory):
    user1 = user_factory(client)
    time1 = datetime.utcnow()
    email_user = AuthMethod(user_id=user1, param="email", auth_method="email", value="testemailx@x.xy")
    dbsession.add(email_user)
    dbsession.commit()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    client.patch(f"/user/{user1}", json={"groups": [group]})
    resp = client.delete(f"user/{user1}")
    assert resp.status_code == 200
    user = dbsession.query(User).filter(User.id == user1).one_or_none()
    assert user.is_deleted
    user_group = dbsession.query(UserGroup).filter(UserGroup.group_id == group).one_or_none()
    assert user_group.is_deleted
    dbsession.delete(email_user)
    dbsession.query(GroupScope).filter(GroupScope.group_id == group).delete()
    dbsession.query(UserGroup).filter(UserGroup.group_id == group).delete()
    dbsession.query(Group).filter(Group.id == group).delete()
    dbsession.commit()
