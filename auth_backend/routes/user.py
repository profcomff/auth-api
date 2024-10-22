import logging
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi_sqlalchemy import db
from sqlalchemy import not_
from sqlalchemy.orm import Session
from starlette.status import HTTP_403_FORBIDDEN

from auth_backend.auth_method import AuthPluginMeta
from auth_backend.auth_plugins.email import Email
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
    user: User = User.get(user_id, session=db.session)  # type: ignore
    auth_params = Email.get_auth_method_params(user.id, session=db.session)
    result = (
        result
        | UserInfo(
            id=user_id,
            email=auth_params["email"].value if "email" in auth_params else None,
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


def get_users_auth_params(auth_method: str, session: Session) -> dict[int, dict[str, AuthMethod]]:
    """Don't use it in public API routes"""
    retval = {}
    methods: list[AuthMethod] = AuthMethod.query(session=session).filter(AuthMethod.auth_method == auth_method).all()
    for method in methods:
        if method.user_id not in retval:
            retval[method.user_id] = {}
        retval[method.user_id][method.param] = method
    return retval


@user.get("", response_model=UsersGet, response_model_exclude_unset=True)
async def get_users(
    _: UserSession = Depends(UnionAuth(scopes=["auth.user.read"], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "scopes", ""]] = Query(default=[]),
) -> dict[str, Any]:
    """
    Scopes: `["auth.user.read"]`
    """
    ##  TODO: Add pagination
    users = User.query(session=db.session).all()
    result = {}
    result["items"] = []
    all_user_auth_params = get_users_auth_params("email", db.session)
    for user in users:
        add = {
            "id": user.id,
            "email": (
                all_user_auth_params[user.id]["email"].value
                if "email" in (all_user_auth_params.get(user.id) or [])
                else None
            ),
        }
        if "groups" in info:
            add["groups"] = [group.id for group in user.groups]
        if "indirect_groups" in info:
            add["indirect_groups"] = [scope.id for scope in user.indirect_groups]
        if "scopes" in info:
            add["scopes"] = user.scopes
        result["items"].append(add)
    return UsersGet(**result).model_dump(exclude_unset=True)


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
    current_user: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
) -> None:
    """
    Scopes: `["auth.user.delete"]` or `["auth.user.selfdelete"]` for self delete
    """
    session_scopes = set([scope.name.lower() for scope in current_user.scopes])
    if "auth.user.delete" in session_scopes or (
        "auth.user.selfdelete" in session_scopes and user_id == current_user.user_id
    ):
        logger.debug(f'User id={current_user.id} triggered delete_user')
        old_user = {"user_id": current_user.id}
        user: User = User.get(user_id, session=db.session)

        for method in user._auth_methods:
            if method.is_deleted:
                continue
            # Сохраняем старое состояние пользователя
            if method.auth_method not in old_user:
                old_user[method.auth_method] = {}
            old_user[method.auth_method][method.param] = method.value
            # Удаляем AuthMethod
            AuthMethod.delete(method.id, session=db.session)
            logger.info(f'{method=} for {user.id=} deleted')
        User.delete(user_id, session=db.session)
        # Удаляем сессии
        db.session.query(UserSession).filter(UserSession.user_id == user_id).filter(not_(UserSession.expired)).update(
            {"expires": datetime.utcnow()}
        )
        db.session.commit()
        await AuthPluginMeta.user_updated(None, old_user)
        logger.info(f'{user=} deleted')
    else:
        raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
