import datetime

import pytest
import datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from auth_backend.models.db import AuthMethod, UserSession

from auth_backend.exceptions import ObjectNotFound
from auth_backend.models.db import Group, UserGroup


def create_scope(client_auth: TestClient, dbsession: Session, user):
    user_id, body, response = user["user_id"], user["body"], user["login_json"]
    response = client_auth.post("/scope", json={"name": "gh.gh.gh"})


def patch_scope(client, dbsession):
    pass


def get_scope(client, dbsession):
    pass


def delete_scope(client, dbsession):
    pass


def get_scopes(client, dbsession):
    pass
