from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi_sqlalchemy import db

from auth_backend.base import StatusResponseModel
from auth_backend.exceptions import AlreadyExists, ObjectNotFound
from auth_backend.models.db import Group as DbGroup
from auth_backend.models.db import GroupScope, Scope, UserSession
from auth_backend.schemas.models import Group, GroupGet, GroupPatch, GroupPost, GroupsGet
from auth_backend.utils.security import UnionAuth


groups = APIRouter(prefix="/group", tags=["Groups"])


@groups.get("/{id}", response_model=GroupGet, response_model_exclude_unset=True)
async def get_group(
    id: int,
    info: list[Literal["child", "scopes", "indirect_scopes", "users"]] = Query(default=[]),
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.group.read"], allow_none=False, auto_error=True)),
) -> dict[str, str | int]:
    """
    Scopes: `["auth.group.read"]`
    """
    group = DbGroup.get(id, session=db.session)
    result = {}
    result = result | Group.model_validate(group).model_dump()
    if "child" in info:
        result["child"] = group.child
    if "scopes" in info:
        result["scopes"] = group.scopes
    if "indirect_scopes" in info:
        result["indirect_scopes"] = group.indirect_scopes
    if "users" in info:
        result["users"] = [user.id for user in group.users]
    return GroupGet(**result).model_dump(exclude_unset=True)


@groups.post("", response_model=Group)
async def create_group(
    group_inp: GroupPost,
    _: UserSession = Depends(UnionAuth(scopes=["auth.group.create"], allow_none=False, auto_error=True)),
) -> dict[str, str | int]:
    """
    Scopes: `["auth.group.create"]`
    """
    if group_inp.parent_id and not db.session.query(DbGroup).get(group_inp.parent_id):
        raise ObjectNotFound(Group, group_inp.parent_id)
    if DbGroup.query(session=db.session).filter(DbGroup.name == group_inp.name).one_or_none():
        raise HTTPException(
            status_code=409,
            detail=StatusResponseModel(
                status="Error", message="Name already exists", ru="Имя уже существует"
            ).model_dump(),
        )
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
    db.session.commit()
    return Group(**result).model_dump(exclude_unset=True)


@groups.patch("/{id}", response_model=Group)
async def patch_group(
    id: int,
    group_inp: GroupPatch,
    _: UserSession = Depends(UnionAuth(scopes=["auth.group.update"], allow_none=False, auto_error=True)),
) -> Group:
    """
    Scopes: `["auth.group.update"]`
    """
    if (
        exists_check := DbGroup.query(session=db.session)
        .filter(DbGroup.name == group_inp.name, DbGroup.id != id)
        .one_or_none()
    ):
        raise AlreadyExists(Group, exists_check.id)
    group = DbGroup.get(id, session=db.session)
    if group_inp.parent_id in (row.id for row in group.child):
        raise HTTPException(
            status_code=400,
            detail=StatusResponseModel(status="Error", message="Cycle detected", ru="Найден цикл").model_dump(),
        )
    result = Group.model_validate(
        DbGroup.update(id, session=db.session, **group_inp.model_dump(exclude_unset=True, exclude={"scopes"}))
    ).model_dump(exclude_unset=True)
    scopes = set()
    if group_inp.scopes is not None:
        for _scope_id in group_inp.scopes:
            scopes.add(Scope.get(session=db.session, id=_scope_id))
        group.scopes = scopes
    db.session.commit()
    return Group.model_validate(group)


@groups.delete("/{id}", response_model=None)
async def delete_group(
    id: int, _: UserSession = Depends(UnionAuth(scopes=["auth.scope.delete"], allow_none=False, auto_error=True))
) -> None:
    """
    Scopes: `["auth.scope.delete"]`
    """
    group: DbGroup = DbGroup.get(id, session=db.session)
    if child := group.child:
        for children in child:
            children.parent_id = group.parent_id
        db.session.flush()
    DbGroup.delete(id, session=db.session)
    db.session.commit()
    return None


@groups.get("", response_model=GroupsGet, response_model_exclude_unset=True)
async def get_groups(
    info: list[Literal["", "scopes", "indirect_scopes", "child", "users"]] = Query(default=[]),
    _: UserSession = Depends(UnionAuth(scopes=["auth.group.read"], allow_none=False, auto_error=True)),
) -> dict[str, Any]:
    """
    Scopes: `["auth.group.read"]`
    """
    groups = DbGroup.query(session=db.session).all()
    result = {}
    result["items"] = []
    for group in groups:
        add = {"id": group.id, "name": group.name, "parent_id": group.parent_id}
        if "scopes" in info:
            add["scopes"] = group.scopes
        if "indirect_scopes" in info:
            add["indirect_scopes"] = group.indirect_scopes
        if "child" in info:
            add["child"] = group.child
        if "users" in info:
            add["users"] = [user.id for user in group.users]
        result["items"].append(add)
    return GroupsGet(**result).model_dump(exclude_unset=True)
