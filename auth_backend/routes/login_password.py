from fastapi import APIRouter, HTTPException
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.models.db import AuthMethod
from auth_backend.settings import get_settings

settings = get_settings()

login_password = APIRouter(prefix="/email", tags=["Email"])


@login_password.get("/approve/email", response_model=None)
async def approve_email(token: str) -> None:
    query: AuthMethod = db.session.query(AuthMethod).filter(AuthMethod.value == token).one_or_none()
    if not query:
        raise HTTPException(status_code=403, detail="Incorrect link")
    for row in query.user.get_auth_methods(LoginPassword.__name__):
        if row.param == "confirmed":
            row.value = True
    db.session.flush()

# TODO Сделать смену пароля, подтверждение изменения
