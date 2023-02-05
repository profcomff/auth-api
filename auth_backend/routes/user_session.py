from datetime import datetime
from typing import Literal, Union

from fastapi import APIRouter, Header, HTTPException
from fastapi_sqlalchemy import db
from starlette.responses import JSONResponse

from auth_backend.base import ResponseModel
from auth_backend.exceptions import AuthFailed
from auth_backend.exceptions import SessionExpired
from auth_backend.models.db import UserSession
from .models.models import UserInfo, UserInfoWithGroups

logout_router = APIRouter(prefix="", tags=["Logout"])


@logout_router.post("/logout", response_model=str)
async def logout(token: str = Header(min_length=1)) -> JSONResponse:
    session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        raise AuthFailed(error="Session not found")
    if session.expired:
        raise SessionExpired(session.token)
    session.expires = datetime.utcnow()
    db.session.commit()
    return JSONResponse(status_code=200, content=ResponseModel(status="Success", message="Logout successful").json())


@logout_router.post("/me", response_model=Union[UserInfoWithGroups, UserInfo])
async def me(
    token: str = Header(min_length=1), info: Literal["me", "with_groups"] = "me"
) -> UserInfo | UserInfoWithGroups:
    if not token:
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Header missing").json())
    session: UserSession = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail=ResponseModel(status="Error", message="Session not found").json())
    if session.expired:
        raise SessionExpired(token)
    match info:
        case "me":
            return UserInfo(id=session.user_id, email=session.user.auth_methods.email.value)
        case "with_groups":
            return UserInfoWithGroups(
                id=session.user_id, email=session.user.auth_methods.email.value, groups=session.user.groups
            )
