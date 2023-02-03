from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.models.db import Group
from .models.models import GroupGet, GroupPost, GroupsGet, GroupPatch
from auth_backend.exceptions import ObjectNotFound, AlreadyExists

groups = APIRouter(prefix="/group")


@groups.get("/{id}", response_model=GroupGet)
async def get_group(id: int) -> GroupGet:
    return GroupGet.from_orm(Group.get(id, session=db.session))


@groups.post("", response_model=GroupGet)
async def create_group(group_inp: GroupPost) -> GroupGet:
    if group_inp.parent_id and not db.session.query(Group).get(group_inp.parent_id):
        raise ObjectNotFound(Group, group_inp.parent_id)
    group = Group.create(session=db.session, **group_inp.dict())
    db.session.commit()
    return GroupGet.from_orm(group)


@groups.patch("/{id}", response_model=GroupGet)
async def patch_group(id: int, group_inp: GroupPatch) -> GroupGet:
    if (exists_check :=
    Group.get_all(session=db.session).filter(Group.name == group_inp.name, Group.id != id).one_or_none()):
        raise AlreadyExists(Group, exists_check.id)
    patched = Group.update(id, session=db.session, **group_inp.dict(exclude_unset=True))
    db.session.commit()
    return GroupGet.from_orm(patched)


@groups.delete("/{id}", response_model=None)
async def delete_group(id: int) -> None:
    group: Group = Group.get(id, session=db.session)
    if childs := group.child:
        for child in childs:
            child.parent = group.parent
        db.session.flush()
    Group.delete(id, session=db.session)
    db.session.commit()
    return None


@groups.get("/{id}", response_model=GroupsGet)
async def get_groups() -> GroupsGet:
    return GroupsGet.from_orm(Group.get_all(session=db.session).all())
