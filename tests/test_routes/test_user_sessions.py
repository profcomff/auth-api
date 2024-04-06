import logging
from datetime import datetime, timedelta
from time import sleep

from sqlalchemy.orm import Session
from starlette import status
from starlette.testclient import TestClient

from auth_backend.models.db import Group, GroupScope, Scope, UserGroup, UserSession, UserSessionScope


logger = logging.getLogger(__name__)


def test_create_session(client_auth: TestClient, dbsession: Session, user_scopes):
    user_id, body, response_ = user_scopes[1]["user_id"], user_scopes[1]["body"], user_scopes[1]["login_json"]
    token = user_scopes[0]
    header = {"Authorization": token}
    params = {"info": ["session_scopes", "token", "expires"]}
    all_sessions = client_auth.get("/session", headers=header, params=params)

    current_session_get = client_auth.get("/me", headers=header)
    assert current_session_get.status_code == status.HTTP_200_OK
    current_session_id_get = dbsession.query(UserSession).filter(UserSession.token == token).one().id
    payload = {'info': 'session_scopes'}
    current_session_scopes_get = client_auth.get("/me", headers=header, params=payload)
    assert current_session_scopes_get.status_code == status.HTTP_200_OK
    bad_header = {"Authorization": f"{token}bad"}
    new_session1 = client_auth.post("/session", headers=header, json={})
    assert new_session1.status_code == status.HTTP_200_OK
    bad_session = client_auth.post("/session", headers=bad_header, json={})
    assert bad_session.status_code == status.HTTP_403_FORBIDDEN
    assert new_session1.json()['user_id'] == user_id
    time = datetime.utcnow()
    body = {"name": f"group{time}", "scopes": []}
    response_group = client_auth.post(url="/group", headers=header, json=body)
    assert response_group.status_code == 200
    group_id = response_group.json()["id"]
    group_response1 = client_auth.patch(f"/user/{user_id}", headers=header, json={"groups": [group_id]})
    assert group_response1.status_code == 200
    scope1 = Scope(name="test.first", creator_id=user_id)
    scope2 = Scope(name="test.second", creator_id=user_id)
    dbsession.add(scope1)
    dbsession.add(scope2)
    dbsession.commit()
    group_response2 = client_auth.patch(
        f"/group/{group_id}",
        headers=header,
        json={"name": f"group{time}", "parent_id": None, "scopes": [scope1.id, scope2.id]},
    )
    assert group_response2.status_code == 200
    new_session2 = client_auth.post("/session", headers=header, json={"scopes": [scope1.name, scope2.name]})
    assert new_session2.status_code == status.HTTP_200_OK
    new_session_: UserSession = dbsession.query(UserSession).get(new_session2.json()["id"])
    assert new_session_.id != current_session_id_get
    assert new_session_.scopes != current_session_scopes_get.json()["session_scopes"]
    time = datetime.utcnow() + timedelta(days=999999)
    new_session3 = client_auth.post("/session", headers=header, json={"expires": str(time)})
    assert new_session3.status_code == status.HTTP_200_OK
    new_session3_: UserSession = dbsession.query(UserSession).get(new_session3.json()['id'])
    assert new_session3_.expires == time
    dbsession.query(UserSessionScope).filter(
        UserSessionScope.scope_id == scope1.id, UserSessionScope.scope_id == scope2.id
    ).delete()
    dbsession.query(GroupScope).filter(GroupScope.scope_id == scope1.id, GroupScope.scope_id == scope2.id).delete()
    dbsession.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.id == new_session1.json()["id"],
        UserSession.id == new_session2.json()["id"],
        UserSession.id == new_session3.json()["id"],
    ).delete()
    dbsession.query(UserGroup).filter(UserGroup.group_id == group_id).delete()
    dbsession.delete(scope1)
    dbsession.delete(scope2)
    dbsession.query(Group).filter(Group.id == group_id).delete()
    dbsession.commit()


def test_delete_session(client_auth: TestClient, dbsession: Session, user_scopes):
    token = user_scopes[0]
    header = {"Authorization": token}
    params = {"info": ["session_scopes", "token", "expires"]}
    all_sessions = client_auth.get("/session", headers=header, params=params)

    new_session_response = client_auth.post("/session", headers=header, json={})
    assert new_session_response.status_code == status.HTTP_200_OK
    new_session_token = new_session_response.json()["token"]
    client_auth.delete(f"/session/{new_session_token}", headers=header)
    new_session: UserSession = dbsession.query(UserSession).get(new_session_response.json()["id"])
    assert new_session.expired
    delete_header = {"Authorization": new_session_token}
    new_session_response_deleted = client_auth.get("/me", headers=delete_header)
    assert new_session_response_deleted.status_code == status.HTTP_403_FORBIDDEN


def test_delete_sessions_without_current(client_auth: TestClient, dbsession: Session, user_scopes):
    token = user_scopes[0]
    header = {"Authorization": token}
    params = {"info": ["session_scopes", "token", "expires"]}
    all_sessions = client_auth.get("/session", headers=header, params=params)

    new_session_response1 = client_auth.post("/session", headers=header, json={})
    assert new_session_response1.status_code == status.HTTP_200_OK
    new_session_token1 = new_session_response1.json()["token"]
    new_session_response2 = client_auth.post("/session", headers=header, json={})
    assert new_session_response2.status_code == status.HTTP_200_OK
    new_session_token2 = new_session_response2.json()["token"]
    delete_params = {"delete_current": False}
    client_auth.delete(f"/session", headers=header, params=delete_params)
    new_session1: UserSession = dbsession.query(UserSession).get(new_session_response1.json()["id"])
    new_session2: UserSession = dbsession.query(UserSession).get(new_session_response2.json()["id"])
    assert new_session1.expired
    assert new_session2.expired
    delete_header1 = {"Authorization": new_session_token1}
    delete_header2 = {"Authorization": new_session_token2}
    new_session_response_deleted = client_auth.get("/me", headers=delete_header1)
    assert new_session_response_deleted.status_code == status.HTTP_403_FORBIDDEN
    new_session_response_deleted = client_auth.get("/me", headers=delete_header2)
    assert new_session_response_deleted.status_code == status.HTTP_403_FORBIDDEN


def test_delete_sessions_with_current(client_auth: TestClient, dbsession: Session, user_scopes):
    token = user_scopes[0]
    header = {"Authorization": token}
    params = {"info": ["session_scopes", "token", "expires"]}
    all_sessions = client_auth.get("/session", headers=header, params=params)

    current_session_id_get = client_auth.get("/me", headers=header)
    assert current_session_id_get.status_code == status.HTTP_200_OK
    new_session_response1 = client_auth.post("/session", headers=header, json={})
    assert new_session_response1.status_code == status.HTTP_200_OK
    new_session_token1 = new_session_response1.json()["token"]
    new_session_response2 = client_auth.post("/session", headers=header, json={})
    assert new_session_response2.status_code == status.HTTP_200_OK
    new_session_token2 = new_session_response2.json()["token"]
    delete_params = {"delete_current": True}
    client_auth.delete(f"/session", headers=header, params=delete_params)
    current_session: UserSession = dbsession.query(UserSession).filter(UserSession.token == token).one_or_none()
    new_session1: UserSession = dbsession.query(UserSession).get(new_session_response1.json()["id"])
    new_session2: UserSession = dbsession.query(UserSession).get(new_session_response2.json()["id"])
    assert current_session.expired
    assert new_session1.expired
    assert new_session2.expired
    delete_header1 = {"Authorization": new_session_token1}
    delete_header2 = {"Authorization": new_session_token2}
    new_session_response_deleted = client_auth.get("/me", headers=delete_header1)
    assert new_session_response_deleted.status_code == status.HTTP_403_FORBIDDEN
    new_session_response_deleted = client_auth.get("/me", headers=delete_header2)
    assert new_session_response_deleted.status_code == status.HTTP_403_FORBIDDEN
    current_session_deleted = client_auth.get("/me", headers=header)
    assert current_session_deleted.status_code == status.HTTP_403_FORBIDDEN


def test_get_sessions(client_auth: TestClient, dbsession: Session, user_scopes):
    params = {"info": ["session_scopes", "token", "expires"]}
    token = user_scopes[0]
    header = {"Authorization": token}
    current_session_id_get = client_auth.get("/me", headers=header)
    assert current_session_id_get.status_code == status.HTTP_200_OK
    new_session_response1 = client_auth.post("/session", headers=header, json={})
    assert new_session_response1.status_code == status.HTTP_200_OK
    new_session_response2 = client_auth.post("/session", headers=header, json={})
    assert new_session_response2.status_code == status.HTTP_200_OK
    current_session: UserSession = dbsession.query(UserSession).filter(UserSession.token == token).one_or_none()
    new_session1: UserSession = dbsession.query(UserSession).get(new_session_response1.json()["id"])
    new_session2: UserSession = dbsession.query(UserSession).get(new_session_response2.json()["id"])
    all_sessions = client_auth.get("/session", headers=header, params=params)
    assert current_session.token[-4:] in list(all_sessions.json()[i]['token'] for i in range(len(all_sessions.json())))
    assert new_session1.token[-4:] in list(all_sessions.json()[i]['token'] for i in range(len(all_sessions.json())))
    assert new_session2.token[-4:] in list(all_sessions.json()[i]['token'] for i in range(len(all_sessions.json())))
    client_auth.delete(f'/session/{new_session1.token}', headers=header)
    all_sessions = client_auth.get("/session", headers=header, params=params)
    assert new_session1.token[-4:] not in list(all_sessions.json()[i]['token'] for i in range(len(all_sessions.json())))


def test_patch_session(client_auth: TestClient, dbsession: Session, user_scopes):
    user_id, body, response_ = user_scopes[1]["user_id"], user_scopes[1]["body"], user_scopes[1]["login_json"]
    token = user_scopes[0]
    header = {"Authorization": token}
    params = {"info": ["session_scopes", "token", "expires"]}
    payload = {"session_name": "test_session"}
    new_session1 = client_auth.post("/session", headers=header, json=payload)
    assert new_session1.status_code == status.HTTP_200_OK
    assert new_session1.json()['session_name'] == payload['session_name']
    patch_payload1 = {"session_name": "patch_test_session"}
    patch_session1 = client_auth.patch(f"/session/{new_session1.json()['id']}", headers=header, json=patch_payload1)
    assert patch_session1.status_code == status.HTTP_200_OK
    assert patch_session1.json()['session_name'] == patch_payload1['session_name']
    patch_payload2 = {"session_name": "patch_test_session2", "scopes": ["auth.user.read"]}
    patch_session2 = client_auth.patch(f"/session/{new_session1.json()['id']}", headers=header, json=patch_payload2)
    assert patch_session2.status_code == status.HTTP_403_FORBIDDEN
    get_patch_session2 = client_auth.get("/session", headers=header, params=params)
    assert get_patch_session2.status_code == status.HTTP_200_OK
    for session in get_patch_session2.json():
        if session['id'] == new_session1.json()['id']:
            assert session["session_scopes"] == []
