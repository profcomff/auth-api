import datetime

import pytest

from auth_backend.models.db import Group, UserSession, User


@pytest.mark.skip
def test_scopes_groups(client_auth, dbsession, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    headers = {"Authorization": login["token"]}
    _group1 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1}
    _group2 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2}
    _group3 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": "timetable.event.patch"}, headers=headers)
    assert response.status_code == 200
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    response = client_auth.patch(f"/group/{_group3}", json={"scopes": "timetable.event.get"}, headers=headers)
    assert response.status_code == 200
    response = client_auth.get(f"/group/{_group1}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    assert "timetable.event.get" not in response.json()["scopes"]
    assert "timetable.event.get" not in response.json()["indirect_scopes"]
    response = client_auth.get(f"/group/{_group2}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    assert "timetable.event.get" not in response.json()["scopes"]
    assert "timetable.event.get" not in response.json()["indirect_scopes"]
    response = client_auth.get(f"/group/{_group3}", params={"info": ["indirect_scopes", "scopes"]})
    assert response.json()
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    assert "timetable.event.patch" in response.json()["indirect_scopes"]
    assert "timetable.event.get" in response.json()["scopes"]
    assert "timetable.event.get" in response.json()["indirect_scopes"]
    dbsession.query(UserSession).delete()
    dbsession.query(Group).delete()
    dbsession.query(User).delete()
    dbsession.commit()


@pytest.mark.skip
def test_scopes_user_session(client_auth, dbsession, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    headers = {"Authorization": login["token"]}
    _group1 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1}
    _group2 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2}
    _group3 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": ["timetable.event.patch"]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.post(f"/group/{_group3}/user", json={"user_id": user_id})
    assert response.status_code == 200
    response = client_auth.post("/login", json=body | {"scopes": ["timetable.event.patch"]})
    assert response.status_code == 200
    token = response.json()["token"]
    response = client_auth.post("/login", json=body | {"scopes": ["timetable.event.get"]})
    assert response.status_code == 403
    response = client_auth.get("/me", headers={"Authorization": token}, params={"info": ["scopes"]})
    assert response.status_code == 200
    assert "timetable.event.patch" in response.json()["scopes"]
    response = client_auth.get("/me", headers={"Authorization": login["token"]}, params={"info": ["scopes"]})
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    response = client_auth.patch(f"/group/{_group3}", json={"scopes": ["timetable.event.patch", "timetable.event.get"]}, headers=headers)
    assert response.status_code == 200
    response = client_auth.post("/login", json=body | {"scopes": ["timetable.event.patch", "timetable.event.get"]})
    assert response.status_code == 200
    token = response.json()["token"]
    response = client_auth.post("/login", json=body | {"scopes": ["timetable.event.get"]})
    assert response.status_code == 200
    response = client_auth.post("/login", json=body | {"scopes": ["timetable.event.patch"]})
    assert response.status_code == 200
    response = client_auth.get("/me", headers={"Authorization": token}, params={"info": ["scopes"]})
    assert response.status_code == 200
    assert "timetable.event.patch" in response.json()["scopes"]
    response = client_auth.get("/me", headers={"Authorization": login["token"]}, params={"info": ["scopes"]})
    assert response.status_code == 200
    assert "timetable.event.patch" not in response.json()["scopes"]
    dbsession.query(UserSession).delete()
    dbsession.query(Group).delete()
    dbsession.query(User).delete()
    dbsession.commit()


@pytest.mark.skip
def test_scopes_user_session_incorect_scopes(client_auth, dbsession, user):
    user_id, body, login = user["user_id"], user["body"], user["login_json"]
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None}
    headers = {"Authorization": login["token"]}
    _group1 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1}
    _group2 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2}
    _group3 = client_auth.post(url="/group", json=body, headers=headers).json()["id"]
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": ["event.patch"]}, headers=headers)
    assert response.status_code == 422
    response = client_auth.patch(f"/group/{_group2}", json={"scopes": ["timetable..post"]}, headers=headers)
    assert response.status_code == 422
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": ["timetable.event."]}, headers=headers)
    assert response.status_code == 422
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": ["timetableevent."]}, headers=headers)
    assert response.status_code == 422
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": ["timetable.event"]}, headers=headers)
    assert response.status_code == 422
    response = client_auth.patch(f"/group/{_group1}", json={"scopes": [".event."]}, headers=headers)
    assert response.status_code == 422
    dbsession.query(UserSession).delete()
    dbsession.query(Group).delete()
    dbsession.query(User).delete()
    dbsession.commit()







