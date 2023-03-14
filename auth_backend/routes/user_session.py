from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query, Depends
from fastapi_sqlalchemy import db
from starlette.responses import JSONResponse

from auth_backend.base import ResponseModel
from auth_backend.exceptions import SessionExpired
from auth_backend.models.db import UserSession, Group
from auth_backend.schemas.models import UserGroups, UserIndirectGroups, UserInfo, UserGet, UserScopes, SessionScopes
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
    return JSONResponse(status_code=200, content=ResponseModel(status="Success", message="Logout successful").json())


@logout_router.get("/me", response_model_exclude_unset=True, response_model=UserGet)
async def me(
    session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    info: list[Literal["groups", "indirect_groups", "session_scopes", "user_scopes", ""]] = Query(default=[]),
) -> dict[str, str | int]:
    result: dict[str, str | int] = {}
    result = (
        result
        | UserInfo(
            id=session.user_id,
            email=session.user.auth_methods.email.value if hasattr(session.user.auth_methods, "email") else None,
        ).dict()
    )
    if "groups" in info:
        result = result | UserGroups(groups=session.user.groups).dict()
    if "indirect_groups" in info:
        groups = frozenset(session.user.groups)
        indirect_groups: set[Group] = set()
        for row in groups:
            indirect_groups = indirect_groups | (set(row.parents))
        result = result | UserIndirectGroups(indirect_groups=indirect_groups | groups).dict()

    if "session_scopes" in info:
        result = result | SessionScopes(session_scopes=list(session.scopes)).dict()
    if "user_scopes" in info:
        result = result | UserScopes(user_scopes=list(session.user.indirect_scopes)).dict()
    return UserGet(**result).dict(exclude_unset=True)
