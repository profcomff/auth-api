import logging
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi_sqlalchemy import db
from sqlalchemy import not_
from starlette.responses import JSONResponse

from auth_backend.auth_plugins.email import Email
from auth_backend.base import StatusResponseModel
from auth_backend.exceptions import ObjectNotFound, SessionExpired
from auth_backend.models.db import AuthMethod, UserSession
from auth_backend.schemas.models import (
    Session,
    SessionPatch,
    SessionPost,
    SessionScopes,
    UserAuthMethods,
    UserGet,
    UserGroups,
    UserIndirectGroups,
    UserInfo,
    UserScopes,
)
from auth_backend.utils import user_session_control
from auth_backend.utils.security import UnionAuth


user_session = APIRouter(prefix="", tags=["User session"])
logger = logging.getLogger(__name__)


@user_session.post("/logout", response_model=StatusResponseModel)
async def logout(
    session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))
) -> JSONResponse:
    if session.expired:
        raise SessionExpired(session.token)
    session.expires = datetime.utcnow()
    db.session.commit()
    return JSONResponse(
        status_code=200,
        content=StatusResponseModel(status="Success", message="Logout successful", ru="Вы успешно вышли").model_dump(),
    )


@user_session.get("/me", response_model_exclude_unset=True, response_model=UserGet)
async def me(
    session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "session_scopes", "user_scopes", "auth_methods"]] = Query(
        default=[]
    ),
) -> dict[str, str | int]:
    auth_params = Email.get_auth_method_params(session.user_id, session=db.session)
    result: dict[str, str | int] = {}
    result = (
        result
        | UserInfo(
            id=session.user_id,
            email=auth_params["email"].value if "email" in auth_params else None,
        ).model_dump()
    )
    if "groups" in info:
        result = result | UserGroups(groups=[group.id for group in session.user.groups]).model_dump()
    if "indirect_groups" in info:
        result = (
            result
            | UserIndirectGroups(indirect_groups=[group.id for group in session.user.indirect_groups]).model_dump()
        )
    if "session_scopes" in info:
        result = result | (
            SessionScopes(session_scopes=session.user.scopes).model_dump()
            if session.is_unbounded
            else SessionScopes(session_scopes=session.scopes).model_dump()
        )
    if "user_scopes" in info:
        result = result | UserScopes(user_scopes=session.user.scopes).model_dump()
    if "auth_methods" in info:
        auth_methods = (
            db.session.query(AuthMethod.auth_method)
            .filter(
                AuthMethod.is_deleted == False,
                AuthMethod.user_id == session.user.id,
            )
            .distinct()
            .all()
        )
        result = result | UserAuthMethods(auth_methods=(a[0] for a in auth_methods)).model_dump()

    return UserGet(**result).model_dump(exclude_unset=True)


@user_session.post("/session", response_model=Session)
async def create_session(
    new_session: SessionPost,
    session: UserSession = Depends(UnionAuth(scopes=["auth.session.create"], allow_none=False, auto_error=True)),
):
    return await user_session_control.create_session(
        session.user,
        new_session.scopes,
        new_session.expires,
        db_session=db.session,
        session_name=new_session.session_name,
        is_unbounded=new_session.is_unbounded,
    )


@user_session.delete("/session/{token}")
async def delete_session(
    token: str, current_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))
):
    session: UserSession = (
        UserSession.query(session=db.session)
        .filter(not_(UserSession.expired), UserSession.token.ilike(f'%{token}'))
        .one_or_none()
    )
    if not session:
        raise ObjectNotFound(UserSession, token[-4:])
    if current_session.user is not session.user:
        raise ObjectNotFound(UserSession, token[-4:])
    session.expires = datetime.utcnow()
    db.session.commit()


@user_session.delete("/session")
async def delete_sessions(
    delete_current: bool = Query(default=False),
    current_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
):
    query = (
        db.session.query(UserSession)
        .filter(UserSession.user_id == current_session.user_id)
        .filter(not_(UserSession.expired))
    )
    if not delete_current:
        query = query.filter(UserSession.token != current_session.token)
    query.update({"expires": datetime.utcnow()})
    db.session.commit()


@user_session.get("/session", response_model=list[Session])
async def get_sessions(
    current_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    info: list[Literal["session_scopes", "token", "expires"]] = Query(default=[]),
):
    all_sessions = []
    for session in current_session.user.active_sessions:
        result = dict(
            user_id=session.user_id,
            id=session.id,
            last_activity=session.last_activity,
            session_name=session.session_name,
            is_unbounded=session.is_unbounded,
        )
        if "session_scopes" in info:
            result['session_scopes'] = [
                _scope.name for _scope in (session.user.scopes if session.is_unbounded else session.scopes)
            ]
        if "token" in info:
            result['token'] = session.token[-4:]
        if "expires" in info:
            result['expires'] = session.expires
        all_sessions.append(result)
    return all_sessions


@user_session.patch("/session/{id}", response_model=Session)
async def update_session(
    id: int,
    session_update_info: SessionPatch,
    current_session: UserSession = Depends(
        UnionAuth(scopes=["auth.session.update"], allow_none=False, auto_error=True)
    ),
) -> Session:
    update_session: UserSession = (
        UserSession.query(session=db.session)
        .filter(UserSession.user_id == current_session.user_id, UserSession.id == id)
        .one_or_none()
    )
    if update_session is None:
        raise ObjectNotFound(UserSession, id)
    update_session.update(
        update_session.id, session=db.session, **session_update_info.model_dump(exclude_unset=True, exclude={'scopes'})
    )
    if session_update_info.scopes is not None:
        scopes = await user_session_control.create_scopes_set_by_names(session_update_info.scopes)
        await user_session_control.check_scopes(scopes, current_session.user)
        update_session.scopes = list(scopes)
    db.session.commit()
    return Session(
        session_name=session_update_info.session_name,
        user_id=current_session.user_id,
        token=update_session.token,
        id=id,
        expires=update_session.expires,
        session_scopes=[_scope.name for _scope in update_session.scopes],
        last_activity=update_session.last_activity,
    )
