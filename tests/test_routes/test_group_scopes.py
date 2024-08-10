import datetime

from auth_backend.models.db import Group, GroupScope, Scope, UserGroup


def test_scopes_groups(client_auth, dbsession, user_scopes):
    token = user_scopes[0]
    scope1 = dbsession.query(Scope).filter(Scope.name == "auth.group.create").one()
    scope2 = dbsession.query(Scope).filter(Scope.name == "auth.group.update").one()
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    headers = {"Authorization": token}
    _group1 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1, "scopes": []}
    _group2 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2, "scopes": []}
    _group3 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": [scope1.id]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.patch(f"/group/{_group3}", json={"scopes": [scope2.id]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]}, headers=headers)
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["indirect_scopes"]]
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group1).delete()
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group2).delete()
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group3).delete()
    dbsession.query(Group).filter(Group.id == _group3).delete()
    dbsession.query(Group).filter(Group.id == _group2).delete()
    dbsession.query(Group).filter(Group.id == _group1).delete()
    dbsession.commit()


def test_scopes_user_session(client_auth, dbsession, user_scopes):
    token_, user = user_scopes
    user_id, body_user, login = user["user_id"], user["body"], user["login_json"]
    scope1 = dbsession.query(Scope).filter(Scope.name == "auth.group.create").one()
    scope2 = dbsession.query(Scope).filter(Scope.name == "auth.group.update").one()
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": [scope1.id]}
    headers = {"Authorization": token_}
    _group1 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1, "scopes": []}
    _group2 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2, "scopes": [scope2.id]}
    _group3 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": [scope1.id]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.patch(f"/user/{user_id}", json={"groups": [_group3]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope1.name]})
    assert response.status_code == 200
    token = response.json()["token"]
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope2.name + "s"]})
    assert response.status_code == 404
    response = client_auth.get("/me", headers={"Authorization": token}, params={"info": ["session_scopes"]})
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    response = client_auth.get("/me", headers={"Authorization": login["token"]}, params={"info": ["session_scopes"]})
    assert response.status_code == 200
    assert scope2.id not in [row["id"] for row in response.json()["session_scopes"]]
    response = client_auth.patch(f"/group/{_group3}", json={"scopes": [scope1.id, scope2.id]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope1.name, scope2.name]})
    assert response.status_code == 200
    token1 = response.json()["token"]
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope2.name]})
    assert response.status_code == 200
    token2 = response.json()["token"]
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope1.name]})
    assert response.status_code == 200
    token3 = response.json()["token"]
    response = client_auth.get(
        "/me", headers={"Authorization": token1}, params={"info": ["session_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": token2}, params={"info": ["session_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": token3}, params={"info": ["session_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": login["token"]}, params={"info": ["session_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group1).delete()
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group2).delete()
    dbsession.query(GroupScope).filter(GroupScope.group_id == _group3).delete()
    dbsession.query(UserGroup).filter(UserGroup.group_id == _group1).delete()
    dbsession.query(UserGroup).filter(UserGroup.group_id == _group2).delete()
    dbsession.query(UserGroup).filter(UserGroup.group_id == _group3).delete()
    dbsession.query(UserGroup).filter(UserGroup.user_id == user_id).delete()
    dbsession.query(Group).filter(Group.id == _group3).delete()
    dbsession.query(Group).filter(Group.id == _group2).delete()
    dbsession.query(Group).filter(Group.id == _group1).delete()
    dbsession.commit()
