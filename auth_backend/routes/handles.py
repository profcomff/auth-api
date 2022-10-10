from typing import Literal

from fastapi_sqlalchemy import db

from fastapi import APIRouter
from .models import Token, Email
from auth_backend.auth_plugins.auth_interface import AUTH_METHODS

handles = APIRouter(prefix="", tags=["Auth"])


@handles.post("/registration", response_model=Token)
async def registration(type: str, schema: Email) -> Token:
    if type not in AUTH_METHODS.keys():
        raise Exception
    return Token.from_orm(AUTH_METHODS[type].register(db.session, **schema.dict()))



@handles.post("/login", response_model=Token)
async def login(type: str, schema: Email) -> Token:
    if type not in AUTH_METHODS.keys():
        raise Exception
    return Token.from_orm(AUTH_METHODS[type].login(db.session, **schema.dict()))


@handles.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    ...



