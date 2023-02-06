from typing import Literal, Union

from fastapi import APIRouter, HTTPException, Depends
from fastapi_sqlalchemy import db

from auth_backend.models.db import Group
from .models.models import GroupGet, GroupPost, GroupsGet, GroupPatch, GroupGetWithChilds
from auth_backend.exceptions import ObjectNotFound, AlreadyExists
from ..base import ResponseModel
from ..utils.security import UnionAuth

auth = UnionAuth()

groups = APIRouter(prefix="/group", tags=["Groups"])


@groups.get("/{id}", response_model=Union[GroupGetWithChilds, GroupGet])
async def get_group(id: int, info: Literal["", "with_childs"] = "") -> GroupGet:
    group = Group.get(id, session=db.session)
    match info:
        case "":
            return GroupGet.from_orm(group)
        case "with_childs":
            return GroupGetWithChilds.from_orm(group)


@groups.post("", response_model=GroupGet)
async def create_group(group_inp: GroupPost, _: dict[str, str] = Depends(auth)) -> GroupGet:
    if group_inp.parent_id and not db.session.query(Group).get(group_inp.parent_id):
        raise ObjectNotFound(Group, group_inp.parent_id)
    if Group.get_all(session=db.session).filter(Group.name == group_inp.name).one_or_none():
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Name already exists").json())
    group = Group.create(session=db.session, **group_inp.dict())
    db.session.commit()
    return GroupGet.from_orm(group)


@groups.patch("/{id}", response_model=GroupGet)
async def patch_group(id: int, group_inp: GroupPatch, _: dict[str, str] = Depends(auth)) -> GroupGet:
    if (
        exists_check := Group.get_all(session=db.session)
        .filter(Group.name == group_inp.name, Group.id != id)
        .one_or_none()
    ):
        raise AlreadyExists(Group, exists_check.id)
    group = Group.get(id, session=db.session)
    if group_inp.parent_id in (row.id for row in group.childs):
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Cycle detected").json())
    patched = Group.update(id, session=db.session, **group_inp.dict(exclude_unset=True))
    db.session.commit()
    return GroupGet.from_orm(patched)


@groups.delete("/{id}", response_model=None)
async def delete_group(id: int, _: dict[str, str] = Depends(auth)) -> None:
    group: Group = Group.get(id, session=db.session)
    if childs := group.childs:
        for child in childs:
            child.parent = group.parent
        db.session.flush()
    Group.delete(id, session=db.session)
    db.session.commit()
    return None


@groups.get("", response_model=GroupsGet)
async def get_groups() -> GroupsGet:
    return GroupsGet(items=Group.get_all(session=db.session).all())
