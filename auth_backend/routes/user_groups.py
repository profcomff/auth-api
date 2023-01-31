from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.models.db import Group, UserGroup
from .models.models import GroupGet, GroupPost, GroupsGet, GroupPatch, UserGroupGet, GroupUserListGet

user_groups = APIRouter(prefix="/group/{id}/user")


@user_groups.post("/{user_id}", response_model=UserGroupGet)
async def add_user_to_group(id: int, user_id: int) -> UserGroupGet:
    return UserGroupGet.from_orm(UserGroup.create(session=db.session, user_id=user_id, group_id=id))


@user_groups.get("", response_model=GroupUserListGet)
async def group_user_list(id: int) -> GroupUserListGet:
    group: Group = Group.get(id, session=db.session)
    return GroupUserListGet(items=group.users)


@user_groups.delete("{user_id}")
async def delete_user_from_group(id: int, user_id: int):
    pass


