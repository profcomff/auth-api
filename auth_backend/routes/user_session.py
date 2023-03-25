from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Depends
from fastapi_sqlalchemy import db
from starlette.responses import JSONResponse

from auth_backend.base import ResponseModel
from auth_backend.exceptions import SessionExpired
from auth_backend.models.db import AuthMethod, UserSession
from auth_backend.schemas.models import (
    UserAuthMethods,
    UserGroups,
    UserIndirectGroups,
    UserInfo,
    UserGet,
    UserScopes,
    SessionScopes,
)
from auth_backend.utils.security import UnionAuth

logout_router = APIRouter(prefix="", tags=["Logout"])


@logout_router.post("/logout", response_model=str)
async def logout(
    session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True))
) -> JSONResponse:
    if session.expired:
        raise SessionExpired(session.token)
    session.expires = datetime.utcnow()
    db.session.commit()
    return JSONResponse(status_code=200, content=ResponseModel(status="Success", message="Logout successful").dict())


@logout_router.get("/me", response_model_exclude_unset=True, response_model=UserGet)
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
