from typing import Optional, Union

from fastapi import FastAPI
from fastapi_sqlalchemy import DBSessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse

from .auth import auth
from .login_password import login_password
from auth_backend.exceptions import ObjectNotFound, IncorrectAuthType, SessionExpired, AlreadyExists

from auth_backend.settings import get_settings

settings = get_settings()

app = FastAPI()

@app.exception_handler(ObjectNotFound)
async def not_found_handler(req, exc: ObjectNotFound):
    return PlainTextResponse(f"{exc}", status_code=404)


@app.exception_handler(IncorrectAuthType)
async def not_found_handler(req, exc: IncorrectAuthType):
    return PlainTextResponse(f"{exc}", status_code=403)


@app.exception_handler(SessionExpired)
async def not_found_handler(req, exc: SessionExpired):
    return PlainTextResponse(f"{exc}", status_code=403)


@app.exception_handler(AlreadyExists)
async def not_found_handler(req, exc: AlreadyExists):
    return PlainTextResponse(f"{exc}", status_code=409)


@app.exception_handler(Exception)
async def http_error_handler(req, exc):
    return PlainTextResponse("Error", status_code=500)


app.add_middleware(
    DBSessionMiddleware,
    db_url=settings.DB_DSN,
    session_args={"autocommit": True},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=settings.CORS_ALLOW_HEADERS,
)

app.include_router(auth)
app.include_router(login_password)
