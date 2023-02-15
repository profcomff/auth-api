from typing import Literal

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi_sqlalchemy import db

from auth_backend.exceptions import ObjectNotFound, AlreadyExists
from auth_backend.models.db import Group as DbGroup, UserSession
from auth_backend.routes.models.models import Group, GroupPost, GroupsGet, GroupPatch, GroupGet
from auth_backend.base import ResponseModel
from auth_backend.utils.security import UnionAuth

auth = UnionAuth()

groups = APIRouter(prefix="/group", tags=["Groups"])


@groups.get("/{id}", response_model=GroupGet, response_model_exclude_unset=True)
async def get_group(id: int, info: list[Literal["child"]] = Query(default=[])) -> dict[str, str | int]:
    group = DbGroup.get(id, session=db.session)
    result = {}
    result = result | Group.from_orm(group).dict()
    if "child" in info:
        result = result | {"child": group.child}
    return GroupGet(**result).dict(exclude_unset=True)


@groups.post("", response_model=Group)
async def create_group(group_inp: GroupPost, _: UserSession = Depends(auth)) -> Group:
    if group_inp.parent_id and not db.session.query(DbGroup).get(group_inp.parent_id):
        raise ObjectNotFound(Group, group_inp.parent_id)
    if DbGroup.query(session=db.session).filter(DbGroup.name == group_inp.name).one_or_none():
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Name already exists").json())
    group = DbGroup.create(session=db.session, **group_inp.dict())
    db.session.commit()
    return Group.from_orm(group)


@groups.patch("/{id}", response_model=Group)
async def patch_group(id: int, group_inp: GroupPatch, _: UserSession = Depends(auth)) -> Group:
    if (
        exists_check := DbGroup.query(session=db.session)
        .filter(DbGroup.name == group_inp.name, DbGroup.id != id)
        .one_or_none()
    ):
        raise AlreadyExists(Group, exists_check.id)
    group = DbGroup.get(id, session=db.session)
    if group_inp.parent_id in (row.id for row in group.child):
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Cycle detected").json())
    patched = DbGroup.update(id, session=db.session, **group_inp.dict(exclude_unset=True))
    db.session.commit()
    return Group.from_orm(patched)


@groups.delete("/{id}", response_model=None)
async def delete_group(id: int, _: UserSession = Depends(auth)) -> None:
    group: DbGroup = DbGroup.get(id, session=db.session)
    if child := group.child:
        for children in child:
            children.parent_id = group.parent_id
        db.session.flush()
    DbGroup.delete(id, session=db.session)
    db.session.commit()
    return None


@groups.get("", response_model=GroupsGet)
async def get_groups() -> GroupsGet:
    return GroupsGet(items=DbGroup.query(session=db.session).all())