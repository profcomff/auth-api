from datetime import datetime

from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.exceptions import AuthFailed
from auth_backend.models.db import UserSession

logout_router = APIRouter(prefix="", tags=["Logout"])


@logout_router.post("/logout", response_model=None)
async def logout(token: str) -> None:
    session = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
    if not session:
        raise AuthFailed(error="Session not found")
    if session.expired:
        raise AuthFailed(error="Session expired, log in system again")
    session.expires = datetime.utcnow()
    db.session.flush()
