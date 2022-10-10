import datetime

from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.auth_interface import AUTH_METHODS
from auth_backend.models.db import Session as DbSession
from auth_backend.routes.models.base import Token, Session
from auth_backend.routes.models.login_password import LoginPasswordPost, LoginPasswordPatch

auth = APIRouter(prefix="", tags=["Auth"])


@auth.post("/registration", response_model=Session)
async def registration(type: str, schema: LoginPasswordPost) -> Session:
    if type not in AUTH_METHODS.keys():
        raise Exception
    if not schema.represents_check(AUTH_METHODS[type]):
        raise Exception
    auth = AUTH_METHODS[type](**schema.dict())
    return Session.from_orm(auth.register(db.session))


@auth.post("/login", response_model=Session)
async def login(type: str, schema: LoginPasswordPost) -> Session:
    if type not in AUTH_METHODS.keys():
        raise Exception
    if not schema.represents_check(AUTH_METHODS[type]):
        raise Exception
    auth = AUTH_METHODS[type](**schema.dict())
    return Session.from_orm(auth.login(db.session))


@auth.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    session: DbSession = db.session.query(DbSession).filter(DbSession.token == token.token).one_or_none()
    if session.expired():
        raise Exception
    session.expires = datetime.datetime.utcnow()
    db.session.flush()
    return None


@auth.post("/security", response_model=None)
async def change_params(type: str, token: Token, schema: LoginPasswordPatch) -> None:
    if not schema.represents_check(AUTH_METHODS[type]):
        raise Exception
    return AUTH_METHODS[type].change_params(token, db.session, **schema.dict())
