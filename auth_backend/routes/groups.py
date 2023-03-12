from typing import Literal, Any

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi_sqlalchemy import db

from auth_backend.base import ResponseModel
from auth_backend.exceptions import ObjectNotFound, AlreadyExists
from auth_backend.models.db import Group as DbGroup, UserSession, GroupScope, Scope
from auth_backend.schemas.models import Group, GroupPost, GroupsGet, GroupPatch, GroupGet
from auth_backend.utils.security import UnionAuth

groups = APIRouter(prefix="/group", tags=["Groups"])


@groups.get("/{id}", response_model=GroupGet, response_model_exclude_unset=True)
async def get_group(
    id: int, info: list[Literal["child", "scopes", "indirect_scopes"]] = Query(default=[])
) -> dict[str, str | int]:
    group = DbGroup.get(id, session=db.session)
    result = {}
    result = result | Group.from_orm(group).dict()
    if "child" in info:
        result["child"] = group.child
    if "scopes" in info:
        result["scopes"] = group.scopes
    if "indirect_scopes" in info:
        result["indirect_scopes"] = group.indirect_scopes
    return GroupGet(**result).dict(exclude_unset=True)


@groups.post("", response_model=Group)
async def create_group(
    group_inp: GroupPost,
    _: UserSession = Depends(UnionAuth(scopes=["auth.group.create"], allow_none=False, auto_error=True)),
) -> dict[str, str | int]:
    if group_inp.parent_id and not db.session.query(DbGroup).get(group_inp.parent_id):
        raise ObjectNotFound(Group, group_inp.parent_id)
    if DbGroup.query(session=db.session).filter(DbGroup.name == group_inp.name).one_or_none():
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Name already exists").json())
    scopes = set()
    if group_inp.scopes:
        for _scope_id in group_inp.scopes:
            scopes.add(Scope.get(session=db.session, id=_scope_id))
    result = {}
    group = DbGroup.create(session=db.session, name=group_inp.name, parent_id=group_inp.parent_id)
    db.session.flush()
    result = result | {"name": group.name, "id": group.id, "parent_id": group.parent_id}
    for scope in scopes:
        GroupScope.create(session=db.session, group_id=group.id, scope_id=scope.id)
    db.session.flush()
    result["scopes"] = list(group.scopes)
    db.session.commit()
    return GroupGet(**result).dict(exclude_unset=True)


@groups.patch("/{id}", response_model=Group)
async def patch_group(
    id: int,
    group_inp: GroupPatch,
    _: UserSession = Depends(UnionAuth(scopes=["auth.group.update"], allow_none=False, auto_error=True)),
) -> Group:
    if (
        exists_check := DbGroup.query(session=db.session)
        .filter(DbGroup.name == group_inp.name, DbGroup.id != id)
        .one_or_none()
    ):
        raise AlreadyExists(Group, exists_check.id)
    group = DbGroup.get(id, session=db.session)
    if group_inp.parent_id in (row.id for row in group.child):
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Cycle detected").json())
    result = Group.from_orm(
        DbGroup.update(id, session=db.session, **group_inp.dict(exclude_unset=True, exclude={"scopes"}))
    ).dict(exclude_unset=True)
    scopes = set()
    if group_inp.scopes:
        for _scope_id in group_inp.scopes:
            scopes.add(Scope.get(session=db.session, id=_scope_id))
    if scopes:
        group.scopes = scopes
    db.session.commit()
    return Group.from_orm(group)


@groups.delete("/{id}", response_model=None)
async def delete_group(
    id: int, _: UserSession = Depends(UnionAuth(scopes=["auth.scope.delete"], allow_none=False, auto_error=True))
) -> None:
    group: DbGroup = DbGroup.get(id, session=db.session)
    if child := group.child:
        for children in child:
            children.parent_id = group.parent_id
        db.session.flush()
    DbGroup.delete(id, session=db.session)
    db.session.commit()
    return None


@groups.get("", response_model=GroupsGet, response_model_exclude_unset=True)
async def get_groups(info: list[Literal["", "scopes", "indirect_scopes", "child"]] = Query(default=[])) -> dict[
    str, Any]:
    groups = DbGroup.query(session=db.session).all()
    result = {}
    print(groups)
    result = result | GroupsGet(items=groups).dict()
    if "scopes" not in info:
        for row in result["items"]:
            del row["scopes"]
    if "indirect_scopes" not in info:
        for row in result["items"]:
            del row["indirect_scopes"]
    if "child" not in info:
        for row in result["items"]:
            del row["child"]
    return GroupsGet(**result).dict(exclude_unset=True)
