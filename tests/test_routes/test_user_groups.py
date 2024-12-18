from datetime import datetime

from sqlalchemy.orm import Session
from starlette import status
from starlette.testclient import TestClient

from auth_backend.models.db import Group, User, UserGroup


def test_add_user(client: TestClient, dbsession: Session, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    response = client.patch(f"/user/{user1}", json={"groups": [group]})
    response_get = client.get(f"/user/{user1}", params={"info": ["groups"]})
    assert response.status_code == status.HTTP_200_OK
    usergroup = (
        dbsession.query(UserGroup)
        .filter(UserGroup.user_id == response.json()["id"], UserGroup.group_id == response_get.json()["groups"][0])
        .one_or_none()
    )
    assert usergroup
    gr = Group.get(group, session=dbsession)
    user = User.get(usergroup.user_id, session=dbsession)
    assert user in gr.users
    assert gr in user.groups

    for row in dbsession.query(UserGroup).filter(UserGroup.user_id == user1).all():
        dbsession.delete(row)
    dbsession.delete(gr)
    dbsession.commit()


def test_get_user_list(client, dbsession, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.patch(f"/user/{user1}", json={"groups": [group]})
    response2 = client.patch(f"/user/{user2}", json={"groups": [group]})
    response3 = client.patch(f"/user/{user3}", json={"groups": [group]})
    assert response1.status_code == 200
    assert response2.status_code == 200
    assert response3.status_code == 200
    gr = Group.get(group, session=dbsession)
    response = client.get(f"/group/{group}", params={"info": ["users"]})
    user1_response = client.get(f"/user/{user1}", params={"info": ["groups"]})
    user2_response = client.get(f"/user/{user2}", params={"info": ["groups"]})
    user3_response = client.get(f"/user/{user3}", params={"info": ["groups"]})
    assert user1_response.status_code == 200
    assert user2_response.status_code == 200
    assert user3_response.status_code == 200
    assert group in user1_response.json()["groups"]
    assert group in user2_response.json()["groups"]
    assert group in user3_response.json()["groups"]
    _response = client.get(f"/group", params={"info": ["users"]})
    assert response.json()["id"] in [row["id"] for row in _response.json()["items"]]
    assert response1.json()["id"] in response.json()["users"]
    assert response2.json()["id"] in response.json()["users"]
    assert response3.json()["id"] in response.json()["users"]
    assert len(gr.users) == 3
    us1 = User.get(response1.json()["id"], session=dbsession)
    us2 = User.get(response2.json()["id"], session=dbsession)
    us3 = User.get(response3.json()["id"], session=dbsession)
    assert us1 in gr.users
    assert us2 in gr.users
    assert us3 in gr.users

    for user_id in [user1, user2, user3]:
        for row in dbsession.query(UserGroup).filter(UserGroup.user_id == user_id).all():
            dbsession.delete(row)
        dbsession.commit()
    dbsession.delete(gr)
    dbsession.commit()


def test_del_user_from_group(client, dbsession, user_factory):
    time1 = datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    user1 = user_factory(client)
    user2 = user_factory(client)
    user3 = user_factory(client)
    response1 = client.patch(f"/user/{user1}", json={"groups": [group]})
    response2 = client.patch(f"/user/{user2}", json={"groups": [group]})
    response3 = client.patch(f"/user/{user3}", json={"groups": [group]})
    assert response1.status_code == 200
    assert response2.status_code == 200
    assert response3.status_code == 200
    gr = Group.get(group, session=dbsession)
    response = client.get(f"/group/{group}", params={"info": ["users"]})
    assert response.status_code == 200
    assert response1.json()["id"] in response.json()["users"]
    assert response2.json()["id"] in response.json()["users"]
    assert response3.json()["id"] in response.json()["users"]
    response_patch = client.patch(f"/user/{response2.json()['id']}", json={"groups": []})
    assert response_patch.status_code == 200
    response = client.get(f"/group/{group}", params={"info": ["users"]})
    assert response.status_code == 200
    assert response1.json()["id"] in response.json()["users"]
    assert response2.json()["id"] not in response.json()["users"]
    assert response3.json()["id"] in response.json()["users"]
    us1 = User.get(response1.json()["id"], session=dbsession)
    us2 = User.get(response2.json()["id"], session=dbsession)
    us3 = User.get(response3.json()["id"], session=dbsession)
    assert us1 in gr.users
    assert us2 not in gr.users
    assert us3 in gr.users
    gr.users.clear()
    gr.delete(id=group, session=dbsession)
    dbsession.commit()

    for user_id in [user1, user2, user3]:
        for row in dbsession.query(UserGroup).filter(UserGroup.user_id == user_id).all():
            dbsession.delete(row)
    dbsession.delete(gr)
    dbsession.commit()
