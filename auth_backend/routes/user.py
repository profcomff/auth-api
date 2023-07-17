import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi_sqlalchemy import db

from auth_backend.models.db import AuthMethod, Group, User, UserGroup, UserSession
from auth_backend.schemas.models import User as UserModel
from auth_backend.schemas.models import (
    UserAuthMethods,
    UserGet,
    UserGroups,
    UserIndirectGroups,
    UserInfo,
    UserPatch,
    UserScopes,
    UsersGet,
)
from auth_backend.utils.security import UnionAuth


logger = logging.getLogger(__name__)
user = APIRouter(prefix="/user", tags=["User"])


@user.get("/{user_id}", response_model=UserGet)
async def get_user(
    user_id: int,
    info: list[Literal["groups", "indirect_groups", "scopes", "auth_methods"]] = Query(default=[]),
    _: UserSession = Depends(UnionAuth(scopes=["auth.user.read"], allow_none=False, auto_error=True)),
) -> dict[str, Any]:
    """
    Scopes: `["auth.user.read"]`
    """
    result: dict[str, str | int] = {}
    user = User.get(user_id, session=db.session)
    result = (
        result
        | UserInfo(
            id=user_id,
            email=user.auth_methods.email.email.value if user.auth_methods.email.email else None,
        ).model_dump()
    )
    if "groups" in info:
        result = result | UserGroups(groups=[group.id for group in user.groups]).model_dump()
    if "indirect_groups" in info:
        result = result | UserIndirectGroups(indirect_groups=[group.id for group in user.indirect_groups]).model_dump()
    if "scopes" in info:
        result = result | UserScopes(user_scopes=user.scopes).model_dump()
    if "auth_methods" in info:
        auth_methods = (
            db.session.query(AuthMethod.auth_method)
            .filter(
                AuthMethod.is_deleted == False,
                AuthMethod.user_id == user.id,
            )
            .distinct()
            .all()
        )
        result = result | UserAuthMethods(auth_methods=(a[0] for a in auth_methods)).model_dump()
    return UserGet(**result).model_dump(exclude_unset=True, exclude={"session_scopes"})


@user.get("", response_model=UsersGet, response_model_exclude_unset=True)
async def get_users(
    _: UserSession = Depends(UnionAuth(scopes=["auth.user.read"], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "scopes", ""]] = Query(default=[]),
) -> dict[str, Any]:
    """
    Scopes: `["auth.user.read"]`
    """
    users = User.query(session=db.session).all()
    result = {}
    result["items"] = []
    for user in users:
        add = {
            "id": user.id,
            "email": user.auth_methods.email.email.value if user.auth_methods.email.email else None,
        }
        if "groups" in info:
            add["groups"] = [group.id for group in user.groups]
        if "indirect_groups" in info:
            add["indirect_groups"] = [scope.id for scope in user.indirect_groups]
        if "scopes" in info:
            add["scopes"] = user.scopes
        result["items"].append(add)
    return UsersGet(**result).model_dump(exclude_unset=True, exclude={"session_scopes"})


@user.patch("/{user_id}", response_model=UserModel)
async def patch_user(
    user_id: int,
    user_inp: UserPatch,
    _: UserSession = Depends(UnionAuth(scopes=["auth.user.update"], allow_none=False, auto_error=True)),
) -> UserInfo:
    """
    Scopes: `["auth.user.update"]`
    """
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
    return UserModel.model_validate(user)


@user.delete("/{user_id}", response_model=None)
async def delete_user(
    user_id: int,
    current_user: UserSession = Depends(UnionAuth(scopes=["auth.user.delete"], allow_none=False, auto_error=True)),
) -> None:
    """
    Scopes: `["auth.user.delete"]`
    """
    logger.debug(f'User id={current_user.id} triggered delete_user')
    user: User = User.get(user_id, session=db.session)
    for method in user._auth_methods:
        AuthMethod.delete(method.id, session=db.session)
        logger.info(f'{method=} for {user.id=} deleted')

    User.delete(user_id, session=db.session)
    logger.info(f'{user=} deleted')

    return None
