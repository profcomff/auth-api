from typing import Literal

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi_sqlalchemy import db

from auth_backend.exceptions import ObjectNotFound, AlreadyExists
from auth_backend.models.db import Group as DbGroup, UserSession, Scope, GroupScope
from auth_backend.routes.models.models import Group, GroupPost, GroupsGet, GroupPatch, GroupGet
from auth_backend.base import ResponseModel
from auth_backend.utils.security import UnionAuth

auth = UnionAuth()

group_scopes = APIRouter(prefix="/group/{group_id}/scopes", tags=["Group Scopes"])

@group_scopes.post("/{scope_id}", response_model=None)
async def create_group_scope(group_id: int, scope_id: int,  _: UserSession = Depends(auth)):
    group: DbGroup = DbGroup.get(group_id, session=db.session)
    scope = Scope.get(scope_id, session=db.session)
    if scope in group.indirect_scopes:
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Scope already in group_scopes"))
    return GroupScope.create(session=db.session, scope_id=scope_id, group_id=group_id)


@group_scopes.get("/{scope_id}", response_model=None)
async def check_that_scopee_in_group_scopes(group_id: int, scope_id: int):
    group: DbGroup = DbGroup.get(group_id, session=db.session)
    scope = Scope.get(scope_id, session=db.session)
    if scope in group.indirect_scopes:
        return ResponseModel(status="Success", message="Scope in group_scopes")
    raise HTTPException(status_code=404, detail=ResponseModel(status="Error", message="Scope not in group_scopes").json())

@group_scopes.get("", response_model=None)
async def get_scopes():
    group: DbGroup = DbGroup.get(group_id, session=db.session)
    return group.indirect_scopes


@group_scopes.delete("/{scope_id}", response_model=None)
async def delete_scope(group_id: int, scope_id: int,  _: UserSession = Depends(auth)):
    group: DbGroup = DbGroup.get(group_id, session=db.session)
    scope = Scope.get(scope_id, session=db.session)
    group_scope = GroupScope.query(session=db.session).filter(GroupScope.scope_id == scope_id, GroupScope.group_id == group_id).one_or_none()
    if not group_scope:
        raise HTTPException(status_code=404, detail=ResponseModel(status="Error", message="Scope not in group_scopes").json())
    return GroupScope.delete(group_scope.id, session=db.session)
