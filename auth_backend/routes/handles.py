import datetime

from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.auth_interface import AUTH_METHODS
from auth_backend.models.db import Session as DbSession
from .models import Token, Email, Session

handles = APIRouter(prefix="", tags=["Auth"])


@handles.post("/registration", response_model=Token)
async def registration(type: str, schema: Email) -> Session:
    if type not in AUTH_METHODS.keys():
        raise Exception
    auth = AUTH_METHODS[type](**schema.dict())
    return Session.from_orm(auth.register(db.session))


@handles.post("/login", response_model=Token)
async def login(type: str, schema: Email) -> Session:
    if type not in AUTH_METHODS.keys():
        raise Exception
    auth = AUTH_METHODS[type](**schema.dict())
    return Session.from_orm(auth.login(db.session))


@handles.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    session: DbSession = db.session.query(DbSession).filter(DbSession.token == token.token).one_or_none()
    if session.expired():
        raise Exception
    session.expires = datetime.datetime.utcnow()
    db.session.flush()
    return None



