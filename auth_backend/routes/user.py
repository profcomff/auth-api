from typing import Literal

from fastapi import APIRouter, Query, Depends
from fastapi_sqlalchemy import db

from auth_backend.models.db import User, UserGroup
from auth_backend.models.db import UserSession, Group
from auth_backend.schemas.models import UserGroups, UserIndirectGroups, UserInfo, UserGet, UserScopes
from auth_backend.schemas.models import UsersGet, UserPatch
from auth_backend.utils.security import UnionAuth

user = APIRouter(prefix="/user", tags=["User"])


@user.get("/{user_id}", response_model=UserGet)
async def get_user(
    user_id: int,
    info: list[Literal["groups", "indirect_groups", "scopes", ""]] = Query(default=[]),
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.user.read"], allow_none=False, auto_error=True)),
) -> UserGet:
    result: dict[str, str | int] = {}
    user = User.get(user_id, session=db.session)
    result = (
        result
        | UserInfo(
            id=user_id,
            email=user.auth_methods.email.value if hasattr(user.auth_methods, "email") else None,
        ).dict()
    )
    if "groups" in info:
        result = result | UserGroups(groups=user.groups).dict()
    if "indirect_groups" in info:
        groups = frozenset(user.groups)
        indirect_groups: set[Group] = set()
        for row in groups:
            indirect_groups = indirect_groups | (set(row.parents))
        result = result | UserIndirectGroups(indirect_groups=indirect_groups | groups).dict()

    if "scopes" in info:
        result = result | UserScopes(user_scopes=list(user.indirect_scopes)).dict()
    return UserGet(**result).dict(exclude_unset=True)


@user.get("", response_model=UsersGet, response_model_exclude_unset=True)
async def get_users(
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.user.read"], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "scopes", ""]] = Query(default=[]),
) -> ...:
    users = User.query(session=db.session).all()
    users = UsersGet(items=users).dict()
    if "groups" not in info:
        for row in users["items"]:
            del row["groups"]
    if "indirect_groups" not in info:
        for row in users["items"]:
            del row["indirect_groups"]
    if "scopes" not in info:
        for row in users["items"]:
            del row["scopes"]
    return UsersGet(**users).dict(exclude_unset=True)


@user.patch("/{user_id}", response_model=UserGet)
async def patch_user(
    user_id: int,
    user_inp: UserPatch,
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.user.update"], allow_none=False, auto_error=True)),
) -> UserGet:
    user = User.get(user_id, session=db.session)
    groups = set()
    for group_id in user_inp.groups:
        group = Group.get(group_id, session=db.session)
        groups.add(group)
    user_groups = set(user.groups)
    new_groups = groups - user_groups
    to_delete_groups = user_groups - groups
    for group in new_groups:
        UserGroup.create(session=db.session, user_id=user_id, group_id=group.id)
    for group in to_delete_groups:
        user_group: UserGroup = (
            UserGroup.query(session=db.session)
            .filter(UserGroup.user_id == user_id, UserGroup.group_id == group.id)
            .one()
        )
        UserGroup.delete(user_group.id, session=db.session)
    db.session.commit()
    return UserGet.from_orm(user)


@user.delete("/{user_id}", response_model=None)
async def delete_user(
    user_id: int,
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.user.delete"], allow_none=False, auto_error=True)),
) -> None:
    User.get(user_id, session=db.session)
    User.delete(user_id, session=db.session)
    return None
