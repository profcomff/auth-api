import datetime

import sqlalchemy
from fastapi import APIRouter
from fastapi_sqlalchemy import db
from sqlalchemy import cast

from auth_backend.auth_plugins.auth_interface import AUTH_METHODS
from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.auth_plugins.email_confirrmation import send_confirmation_email
from auth_backend.models.db import Session as DbSession
from auth_backend.models.db import AuthMethod
from auth_backend.routes.models.base import Token, Session
from auth_backend.settings import get_settings
from auth_backend.routes.models.login_password import LoginPasswordPost, LoginPasswordPatch

settings = get_settings()
auth = APIRouter(prefix="", tags=["Auth"])


@auth.post("/registration", response_model=Session)
async def registration(auth_type: str, schema: LoginPasswordPost, user_id: int | None = None) -> Session:
    if auth_type not in AUTH_METHODS.keys():
        raise Exception
    if not schema.represents_check(AUTH_METHODS[auth_type]):
        raise Exception
    auth = AUTH_METHODS[auth_type](**schema.dict(), salt=None)
    if auth_type == type(LoginPassword):
        link = f"{settings}/approve?token={auth.register(db.session, user_id=user_id)}"
        return send_confirmation_email(subject="Email confirmation", to_addr=schema.email, link=link)
    return Session.from_orm(auth.register(db.session, user_id=user_id))


@auth.post("/login", response_model=Session)
async def login(type: str, schema: LoginPasswordPost) -> Session:
    if type not in AUTH_METHODS.keys():
        raise Exception
    if not schema.represents_check(AUTH_METHODS[type]):
        raise Exception
    salt: str | None = None
    if isinstance(schema, LoginPasswordPost):
        query = (
            db.session.query(AuthMethod)
            .filter(AuthMethod.value == schema.email, AuthMethod.param == "email")
            .one_or_none()
        )
        if not query:
            raise Exception
        if not query.is_active:
            raise Exception
        salt = (
            db.session.query(AuthMethod)
            .filter(AuthMethod.user_id == query.user_id, AuthMethod.param == "salt")
            .one_or_none()
            .value
        )
    auth = AUTH_METHODS[type](**schema.dict(), salt=salt)
    return Session.from_orm(auth.login(db.session))


@auth.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    session: DbSession = db.session.query(DbSession).filter(DbSession.token == token.token).one_or_none()
    if session.expired:
        raise Exception
    session.expires = datetime.datetime.utcnow()
    db.session.flush()
    return None


@auth.post("/security", response_model=None)
async def change_params(type: str, token: Token, schema: LoginPasswordPatch) -> None:
    if not schema.represents_check(AUTH_METHODS[type]):
        raise Exception
    return AUTH_METHODS[type].change_params(token.token, auth_type=AUTH_METHODS[type], db_session=db.session, **schema.dict())
