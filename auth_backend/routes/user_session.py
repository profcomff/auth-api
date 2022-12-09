from datetime import datetime

from fastapi import APIRouter, Header, HTTPException
from fastapi_sqlalchemy import db
from starlette.responses import JSONResponse

from auth_backend.base import ResponseModel
from auth_backend.exceptions import AuthFailed
from auth_backend.exceptions import SessionExpired
from auth_backend.models.db import UserSession

logout_router = APIRouter(prefix="", tags=["Logout"])


@logout_router.post("/logout", response_model=str)
async def logout(token: str = Header(default=None)) -> JSONResponse:
    if not token:
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Header missing").json())
    session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        raise AuthFailed(error="Session not found")
    if session.expired:
        raise SessionExpired(session.token)
    session.expires = datetime.utcnow()
    db.session.flush()
    return JSONResponse(status_code=200, content=ResponseModel(status="Success", message="Logout successful").json())


@logout_router.post("/me", response_model=ResponseModel)
async def me(token: str = Header(default=None)) -> JSONResponse:
    if not token:
        raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Header missing").json())
    session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        return JSONResponse(status_code=404, content=ResponseModel(status="Error", message="Session not found").json())
    if session.expired:
        raise SessionExpired(token)
    return JSONResponse(
        status_code=200, content=ResponseModel(status="Success", message="Session found and exists").json()
    )
