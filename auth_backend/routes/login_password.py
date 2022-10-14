from fastapi import APIRouter, HTTPException
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.models.db import AuthMethod
from auth_backend.settings import get_settings

settings = get_settings()

login_password = APIRouter(prefix="/email", tags=["Email"])


# @login_password.post("/forgot", response_model=str)
# async def forgot_password(email: EmailStr) -> str:
#     return send_change_password_confirmation_email("Password change", to_addr=email, link=f"{settings.host}/approve/password")


@login_password.post("/approve/email", response_model=None)
async def approve_email(token: str) -> None:
    query: AuthMethod = db.session.query(AuthMethod).filter(AuthMethod.value == token).one_or_none()
    if not query:
        raise HTTPException(status_code=403, detail="Incorrect link")
    for row in query.user.get_auth_methods(LoginPassword.__name__):
        if row.param == "confirmed":
            row.value = True
    db.session.flush()


# @login_password.post("/approve/password", response_model=bool)
# async def approve_password_change(token: str):
#     query: list[AuthMethod] = db.session.query(AuthMethod).filter(AuthMethod.token == token).all()
#     if not query:
#         raise Exception
#     for row in query:
#         row.is_active = True
#     db.session.flush()
#     return 200

