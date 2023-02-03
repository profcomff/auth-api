from sqlalchemy.orm import Session
from starlette import status
from starlette.testclient import TestClient

from auth_backend.models.db import UserGroup, Group, User


def test_add_user(client: TestClient, dbsession: Session, group, user_factory):
    group = group(client, None)
    user1 = user_factory(client)
    response = client.post(f"/group/{group}/user/{user1}")
    assert response.status_code == status.HTTP_200_OK
    usergroup = dbsession.query(UserGroup).filter(UserGroup.user_id == response.json()["user_id"], UserGroup.group_id == response.json()["group_id"]).one_or_none()
    assert usergroup
    gr = Group.get(group)
    user = User.get(usergroup.user_id)
    assert user in gr.users
    assert gr in user.groups


def test_get_user_list(client, dbsession, group, user_factory):
    group = group(client, None)
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.post(f"/group/{group}/user/{user1}")
    response2 = client.post(f"/group/{group}/user/{user2}")
    response3 = client.post(f"/group/{group}/user/{user3}")
    gr = Group.get(group)
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in response.json()
    assert response2.json()["user_id"] in response.json()
    assert response3.json()["user_id"] in response.json()
    assert len(gr.users) == 3
    us1 = User.get(response1.json()["user_id"])
    us2 = User.get(response2.json()["user_id"])
    us3 = User.get(response3.json()["user_id"])
    assert us1 in gr.users
    assert us2 in gr.users
    assert us3 in gr.users


def test_del_user_from_group(client, dbsession, group, user_factory):
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.post(f"/group/{group}/user/{user1}")
    response2 = client.post(f"/group/{group}/user/{user2}")
    response3 = client.post(f"/group/{group}/user/{user3}")
    gr = Group.get(group)
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in response.json()
    assert response2.json()["user_id"] in response.json()
    assert response3.json()["user_id"] in response.json()
    client.delete(f"/group/{group}/user/{response2.json()['user_id']}")
    response = client.get(f"/group/{group}/user")
    assert response1.json()["user_id"] in response.json()
    assert response2.json()["user_id"] not in response.json()
    assert response3.json()["user_id"] in response.json()
    us1 = User.get(response1.json()["user_id"])
    us2 = User.get(response2.json()["user_id"])
    us3 = User.get(response3.json()["user_id"])
    assert us1 in gr.users
    assert us2 not in gr.users
    assert us3 in gr.users





