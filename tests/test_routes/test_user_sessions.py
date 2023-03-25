from starlette.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime
from starlette import status
from auth_backend.models.db import UserSession, UserSessionScope, GroupScope, Group
from auth_backend.models.db import Scope


def test_create_session(client_auth: TestClient, dbsession: Session, user_scopes):
    user_id, body, response_ = user_scopes[1]["user_id"], user_scopes[1]["body"], user_scopes[1]["login_json"]
    token = user_scopes[0]
    header = {
        "Authorization": token
    }
    current_session_id_get = client_auth.get("/me", headers=header)
    assert current_session_id_get.status_code == status.HTTP_200_OK
    current_session_scopes_get = client_auth.get("/me", headers=header)
    assert current_session_scopes_get.status_code == status.HTTP_200_OK
    bad_header = {
        "Authorization": f"{token}bad"
    }
    new_session1 = client_auth.post("/session", headers=header, json={})
    assert new_session1.status_code == status.HTTP_200_OK
    bad_session = client_auth.post("/session", headers=bad_header)
    assert bad_session.status_code == status.HTTP_403_FORBIDDEN
    assert new_session1.json()['user_id'] == user_id
    time = datetime.utcnow()
    body = {"name": f"group{time}", "scopes": []}
    response_group = client_auth.post(url="/group", headers=header , json=body)
    assert response_group.status_code == 200
    group_id = response_group.json()["id"]
    group_response1 = client_auth.patch(f"/user/{user_id}",  headers=header, json={"groups": [group_id]})
    assert group_response1.status_code == 200
    scope1 = Scope(name="test.first", creator_id=user_id)
    scope2 = Scope(name="test.second", creator_id=user_id)
    dbsession.add(scope1)
    dbsession.add(scope2)
    dbsession.commit()
    group_response2 = client_auth.patch(f"/group/{group_id}", headers=header, json={"name": f"group{time}", "parent_id": None ,
                                                                                   "scopes": [scope1.id, scope2.id]})
    assert group_response2.status_code == 200
    new_session2 = client_auth.post("/session", headers=header, json={"scopes": [scope1.name, scope2.name]})
    assert new_session2.status_code == status.HTTP_200_OK



    #####################################################################################################
    new_session_: UserSession = dbsession.query(UserSession).get(new_session2.json()["id"])
    assert new_session_.id != current_session_id_get.json()["id"]
    assert new_session_.scopes != current_session_scopes_get.json()["session_scopes"]

    dbsession.query(UserSessionScope).filter(UserSessionScope.scope_id == scope1.id, UserSessionScope.scope_id == scope2.id).delete()
    dbsession.query(GroupScope).filter(GroupScope.scope_id == scope1.id, GroupScope.scope_id == scope2.id).delete()
    dbsession.query(UserSession).filter(UserSession.user_id == user_id, UserSession.id == new_session1.json()["id"],
                                        UserSession.id == new_session2.json()["id"]).delete()
    dbsession.query(Group).filter(Group.id == group_id).delete()
    dbsession.delete(scope1)
    dbsession.delete(scope2)
    dbsession.commit()









