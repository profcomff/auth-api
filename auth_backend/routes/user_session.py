import logging
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi_sqlalchemy import db
from sqlalchemy import not_
from starlette.responses import JSONResponse

from auth_backend.base import StatusResponseModel
from auth_backend.exceptions import ObjectNotFound, SessionExpired
from auth_backend.models.db import AuthMethod, UserSession
from auth_backend.schemas.models import (
    Session,
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
        status_code=200, content=StatusResponseModel(status="Success", message="StatusResponseModel successful").dict()
    )


@user_session.get("/me", response_model_exclude_unset=True, response_model=UserGet)
async def me(
    session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "session_scopes", "user_scopes", "auth_methods"]] = Query(
        default=[]
    ),
) -> dict[str, str | int]:
    result: dict[str, str | int] = {}
    result = (
        result
        | UserInfo(
            id=session.user_id,
            email=session.user.auth_methods.email.email.value if session.user.auth_methods.email.email else None,
        ).dict()
    )
    if "groups" in info:
        result = result | UserGroups(groups=[group.id for group in session.user.groups]).dict()
    if "indirect_groups" in info:
        result = (
            result | UserIndirectGroups(indirect_groups=[group.id for group in session.user.indirect_groups]).dict()
        )
    if "session_scopes" in info:
        result = result | SessionScopes(session_scopes=session.scopes).dict()
    if "user_scopes" in info:
        result = result | UserScopes(user_scopes=session.user.scopes).dict()
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
        result = result | UserAuthMethods(auth_methods=(a[0] for a in auth_methods)).dict()

    return UserGet(**result).dict(exclude_unset=True)


@user_session.post("/session", response_model=Session)
async def create_session(
    new_session: SessionPost, session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))
):
    if new_session.session_name is not None:
        return await user_session_control.create_session(
            session.user, new_session.scopes, new_session.expires, db_session=db.session, session_name=new_session.session_name
        )
    else:
        return await user_session_control.create_session(
            session.user, new_session.scopes, new_session.expires, db_session=db.session
        )


@user_session.delete("/session/{token}")
async def delete_session(
    token: str, current_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))
):
    session: UserSession = (
        UserSession.query(session=db.session)
        .filter(UserSession.token == token, not_(UserSession.expired))
        .one_or_none()
    )
    if not session:
        raise ObjectNotFound(UserSession, token)
    if current_session.user is not session.user:
        raise ObjectNotFound(UserSession, token)
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
async def get_sessions(current_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))):
    all_sessions = []
    for session in current_session.user.active_sessions:
        all_sessions.append(
            dict(
                user_id=session.user_id,
                token=('*' * (len(session.token) - 4) + session.token[-4:]),
                id=session.id,
                expires=session.expires,
                session_scopes=[_scope.name for _scope in session.scopes],
                last_activity=session.last_activity,
                session_name=session.session_name,
            )
        )
    return all_sessions
