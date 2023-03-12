import datetime

import pytest

from auth_backend.models.db import Group, UserSession, User, Scope, UserSessionScope, GroupScope, AuthMethod, UserGroup
from auth_backend.auth_plugins.auth_method import random_string


def test_scopes_groups(client_auth, dbsession, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    dbsession.add(scope1 := Scope(name="auth.group.create", creator_id=user_id))
    dbsession.add(scope2 := Scope(name="auth.group.update", creator_id=user_id))
    token = random_string()
    dbsession.add(user_session := UserSession(user_id=user_id, token=token))
    dbsession.flush()
    dbsession.add(UserSessionScope(scope_id=scope1.id, user_session_id=user_session.id))
    dbsession.add(UserSessionScope(scope_id=scope2.id, user_session_id=user_session.id))
    dbsession.commit()
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
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.patch(f"/group/{_group3}", json={"scopes": [scope2.id]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["indirect_scopes"]]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert scope1.id not in [row["id"] for row in response.json()["scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["indirect_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["indirect_scopes"]]
    dbsession.query(UserSessionScope).delete()
    dbsession.delete(user_session)
    dbsession.query(GroupScope).delete()
    dbsession.query(UserGroup).delete()
    dbsession.query(Group).delete()
    dbsession.query(Scope).delete()
    dbsession.commit()


def test_scopes_user_session(client_auth, dbsession, user):
    user_id, body_user, login = user["user_id"], user["body"], user["login_json"]
    dbsession.add(scope1 := Scope(name="auth.group.create", creator_id=user_id))
    dbsession.add(scope2 := Scope(name="auth.group.update", creator_id=user_id))
    dbsession.add(scope3 := Scope(name="auth.user_group.create", creator_id=user_id))
    token_ = random_string()
    dbsession.add(user_session := UserSession(user_id=user_id, token=token_))
    dbsession.flush()
    dbsession.add(UserSessionScope(scope_id=scope1.id, user_session_id=user_session.id))
    dbsession.add(UserSessionScope(scope_id=scope3.id, user_session_id=user_session.id))
    dbsession.add(UserSessionScope(scope_id=scope2.id, user_session_id=user_session.id))
    dbsession.commit()
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
    response = client_auth.post(f"/group/{_group3}/user", json={"user_id": user_id}, headers=headers)
    assert response.status_code == 200
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope1.name]})
    assert response.status_code == 200
    token = response.json()["token"]
    response = client_auth.post("/email/login", json=body_user | {"scopes": [scope2.name + "s"]})
    assert response.status_code == 404
    response = client_auth.get("/me", headers={"Authorization": token}, params={"info": ["token_scopes"]})
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    response = client_auth.get("/me", headers={"Authorization": login["token"]}, params={"info": ["token_scopes"]})
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
        "/me", headers={"Authorization": token1}, params={"info": ["token_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": token2}, params={"info": ["token_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": token3}, params={"info": ["token_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope1.id in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    response = client_auth.get(
        "/me", headers={"Authorization": login["token"]}, params={"info": ["token_scopes", "user_scopes"]}
    )
    assert response.status_code == 200
    assert scope2.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope1.id not in [row["id"] for row in response.json()["session_scopes"]]
    assert scope2.id in [row["id"] for row in response.json()["user_scopes"]]
    assert scope1.id in [row["id"] for row in response.json()["user_scopes"]]
    dbsession.query(UserSessionScope).delete()
    dbsession.delete(user_session)
    dbsession.query(GroupScope).delete()
    dbsession.query(UserGroup).delete()
    dbsession.query(Group).delete()
    dbsession.query(Scope).delete()
    dbsession.commit()
