import datetime
from types import NoneType
from typing import Union

from fastapi import APIRouter
from fastapi import HTTPException
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.auth_interface import AUTH_METHODS
from auth_backend.auth_plugins.email_confirrmation import send_confirmation_email
from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.models.db import AuthMethod
from auth_backend.models.db import Session as DbSession
from auth_backend.routes.models.base import Token, Session
from auth_backend.routes.models.login_password import LoginPasswordPost, LoginPasswordPatch
from auth_backend.settings import get_settings

settings = get_settings()
auth = APIRouter(prefix="", tags=["Auth"])

DOCS = "https://github.com/profcomff/auth-api"


@auth.post("/registration", response_model=Union[Session, NoneType])
async def registration(auth_type: str, schema: LoginPasswordPost, user_id: int | None = None) -> Session | None:
    if auth_type not in AUTH_METHODS.keys():
        raise HTTPException(status_code=422,
                            detail=f"Incorrect auth type. Check supported auth types at {DOCS}")
    if not schema.represents_check(AUTH_METHODS[auth_type]):
        raise HTTPException(status_code=422,
                            detail=f"Invalid JSON schema. Check docs at {DOCS}")
    auth = AUTH_METHODS[auth_type](**schema.dict(), salt=None)
    if auth_type == LoginPassword.__name__:
        link = f"{settings.host}/email/approve/email?token={auth.register(db.session, user_id=user_id)}"
        return send_confirmation_email(subject="Email confirmation", to_addr=schema.email, link=link)
    return Session.from_orm(auth.register(db.session, user_id=user_id))


@auth.post("/login", response_model=Session)
async def login(auth_type: str, schema: LoginPasswordPost) -> Session:
    if auth_type not in AUTH_METHODS.keys():
        raise HTTPException(status_code=422,
                            detail=f"Incorrect auth type. Check supported auth types at {DOCS}")
    if not schema.represents_check(AUTH_METHODS[auth_type]):
        raise HTTPException(status_code=422,
                            detail=f"Invalid JSON schema. Check docs at {DOCS}")
    salt: str | None = None
    if isinstance(schema, LoginPasswordPost):
        query = (
            db.session.query(AuthMethod)
                .filter(AuthMethod.value == schema.email, AuthMethod.param == "email")
                .one_or_none()
        )
        if not query:
            raise HTTPException(status_code=403, detail="Incorrect login or password")
        salt = (
            db.session.query(AuthMethod)
                .filter(AuthMethod.user_id == query.user_id, AuthMethod.param == "salt")
                .one_or_none()
                .value
        )
    auth = AUTH_METHODS[auth_type](**schema.dict(), salt=salt)
    return Session.from_orm(auth.login(db.session))


@auth.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    session: DbSession = db.session.query(DbSession).filter(DbSession.token == token.token).one_or_none()
    if session.expired:
        raise HTTPException(status_code=403, detail="Session expired, log in system again")
    session.expires = datetime.datetime.utcnow()
    db.session.flush()
    return None


@auth.post("/security", response_model=None)
async def change_params(auth_type: str, token: Token, schema: LoginPasswordPatch) -> None:
    if auth_type not in AUTH_METHODS.keys():
        raise HTTPException(status_code=422,
                            detail=f"Incorrect auth type. Check supported auth types at {DOCS}")
    if not schema.represents_check(AUTH_METHODS[auth_type]):
        raise HTTPException(status_code=422,
                            detail=f"Invalid JSON schema. Check docs at {DOCS}")
    return AUTH_METHODS[auth_type].change_params(token.token, db_session=db.session,
                                                 **schema.dict())
