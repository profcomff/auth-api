from typing import Literal

from fastapi import APIRouter
from .models import Token, Email

handles = APIRouter(prefix="", tags=["Auth"])


@handles.post("/registration", response_model=Token)
async def registration(type: Literal["2"], schema: Email) -> Token:
    ...


@handles.post("/login", response_model=Token)
async def login(type: Literal["2"], schema: Email) -> Token:
    ...


@handles.post("/logout", response_model=None)
async def logout(token: Token) -> None:
    ...



