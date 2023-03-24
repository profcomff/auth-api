import datetime

import pytest
import datetime

from fastapi.testclient import TestClient
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.models.db import AuthMethod, UserSession, Scope, UserSessionScope, GroupScope

from auth_backend.exceptions import ObjectNotFound
from auth_backend.models.db import Group, UserGroup



def test_create_scope(client_auth: TestClient, dbsession: Session, user_scopes):
    token_ = user_scopes[0]
    user_session = dbsession.query(UserSession).filter(UserSession.token == token_).one()
    rand = random_string()
    response = client_auth.post(
        "/scope", json={"name": f"gh.gh.gh{rand}", "comment": "test"}, headers={"Authorization": token_}
    )
    assert response.status_code == 200
    db_resp: Scope = dbsession.query(Scope).filter(func.lower(Scope.name) == f"gh.gh.gh{rand}".lower()).one()
    assert db_resp.name == response.json()["name"]
    assert db_resp.comment == response.json()["comment"]
    assert db_resp.creator_id == user_session.user_id
    dbsession.delete(db_resp)
    dbsession.commit()


def test_patch_scope(client_auth, dbsession, user_scopes):
    token_ = user_scopes[0]
    rand = random_string()
    response = client_auth.post(
        "/scope", json={"name": f"gh.gh.gh{rand}", "comment": "test"}, headers={"Authorization": token_}
    )
    assert response.status_code == 200
    response_get_1 = client_auth.get(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert response_get_1.status_code == 200
    assert response_get_1.json() == response.json()
    rand2 = random_string()
    response_update = client_auth.patch(
        f"/scope/{response.json()['id']}",
        headers={"Authorization": token_},
        json={"name": f"gh.gh.gh{rand2}", "comment": "test2"},
    )
    assert response_update.status_code == 200
    response_get_2 = client_auth.get(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert response_get_2.status_code == 200
    assert response_get_2.json() != response_get_1.json()
    assert response_get_2.json() == response_update.json()
    assert response_get_2.json()["name"] == f"gh.gh.gh{rand2}".lower()
    assert response_get_2.json()["comment"] == "test2"
    db_resp: Scope = dbsession.query(Scope).filter(func.lower(Scope.name) == f"gh.gh.gh{rand2}".lower()).one()
    dbsession.delete(db_resp)
    dbsession.commit()


def test_get_scope(client_auth, dbsession, user_scopes):
    token_ = user_scopes[0]
    rand = random_string()
    response = client_auth.post(
        "/scope", json={"name": f"gh.gh.gh{rand}", "comment": "test"}, headers={"Authorization": token_}
    )
    assert response.status_code == 200
    response_get = client_auth.get(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert response_get.status_code == 200
    assert response_get.json() == response.json()
    db_resp: Scope = dbsession.query(Scope).filter(func.lower(Scope.name) == f"gh.gh.gh{rand}".lower()).one()
    dbsession.delete(db_resp)
    dbsession.commit()

def test_delete_scope(client_auth, dbsession, user_scopes):
    token_ = user_scopes[0]
    rand = random_string()
    response = client_auth.post(
        "/scope", json={"name": f"gh.gh.gh{rand}", "comment": "test"}, headers={"Authorization": token_}
    )
    assert response.status_code == 200
    response_get_1 = client_auth.get(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert response_get_1.status_code == 200
    resp_del = client_auth.delete(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert resp_del.status_code == 200
    response_get_2 = client_auth.get(f"/scope/{response.json()['id']}", headers={"Authorization": token_})
    assert response_get_2.status_code == 404
    db_resp: Scope = dbsession.query(Scope).filter(func.lower(Scope.name) == f"gh.gh.gh{rand}".lower()).one()
    dbsession.delete(db_resp)
    dbsession.commit()



def test_get_scopes(client, dbsession):
    pass
