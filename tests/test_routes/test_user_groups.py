from datetime import datetime

from sqlalchemy.orm import Session
from starlette import status
from starlette.testclient import TestClient

from auth_backend.models.db import UserGroup, Group, User


def test_add_user(client: TestClient, dbsession: Session, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    response = client.post(f"/group/{group}/user", json={"user_id": user1})
    assert response.status_code == status.HTTP_200_OK
    usergroup = dbsession.query(UserGroup).filter(UserGroup.user_id == response.json()["user_id"], UserGroup.group_id == response.json()["group_id"]).one_or_none()
    assert usergroup
    gr = Group.get(group, session=dbsession)
    user = User.get(usergroup.user_id, session=dbsession)
    assert user in gr.users
    assert gr in user.groups


def test_get_user_list(client, dbsession, group, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.post(f"/group/{group}/user", json={"user_id": user1})
    response2 = client.post(f"/group/{group}/user", json={"user_id": user2})
    response3 = client.post(f"/group/{group}/user", json={"user_id": user3})
    gr = Group.get(group, session=dbsession)
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert response2.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert response3.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert len(gr.users) == 3
    us1 = User.get(response1.json()["user_id"], session=dbsession)
    us2 = User.get(response2.json()["user_id"], session=dbsession)
    us3 = User.get(response3.json()["user_id"], session=dbsession)
    assert us1 in gr.users
    assert us2 in gr.users
    assert us3 in gr.users


def test_del_user_from_group(client, dbsession, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.post(f"/group/{group}/user", json={"user_id": user1})
    response2 = client.post(f"/group/{group}/user", json={"user_id": user2})
    response3 = client.post(f"/group/{group}/user", json={"user_id": user3})
    gr = Group.get(group, session=dbsession)
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert response2.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert response3.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    response = client.delete(f"/group/{group}/user/{response2.json()['user_id']}")
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    assert response2.json()["user_id"] not in [row["id"] for row in response.json()["items"]]
    assert response3.json()["user_id"] in [row["id"] for row in response.json()["items"]]
    us1 = User.get(response1.json()["user_id"], session=dbsession)
    us2 = User.get(response2.json()["user_id"], session=dbsession)
    us3 = User.get(response3.json()["user_id"], session=dbsession)
    assert us1 in gr.users
    assert us2 not in gr.users
    assert us3 in gr.users





