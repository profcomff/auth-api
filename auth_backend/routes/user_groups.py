from fastapi import APIRouter
from fastapi_sqlalchemy import db
from starlette.exceptions import HTTPException

from auth_backend.models.db import Group, UserGroup
from .models.models import UserGroupGet, GroupUserListGet
from ..base import ResponseModel

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
    user = db.session.query(UserGroup).filter(UserGroup.user_id == user_id, UserGroup.group_id == id).one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail=ResponseModel(status="Error", message=f"User {user_id=} in group {id=} not found").json())
    db.session.delete(user)
    db.session.commit()



