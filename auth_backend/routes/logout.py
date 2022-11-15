from datetime import datetime

from fastapi import APIRouter
from fastapi_sqlalchemy import db
from starlette.responses import JSONResponse
from auth_backend.exceptions import SessionExpired

from auth_backend.exceptions import AuthFailed
from auth_backend.models.db import UserSession

logout_router = APIRouter(prefix="", tags=["Logout"])


@logout_router.post("/logout", response_model=str)
async def logout(token: str) -> JSONResponse:
    session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        raise AuthFailed(error="Session not found")
    if session.expired:
        raise SessionExpired(session.token)
    session.expires = datetime.utcnow()
    db.session.flush()
    return JSONResponse(status_code=200, content="Successful")
