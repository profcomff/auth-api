from fastapi import FastAPI
from fastapi_sqlalchemy import DBSessionMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse

from auth_backend.auth_plugins.email import Email
from auth_backend.exceptions import ObjectNotFound, IncorrectAuthType, AlreadyExists, AuthFailed
from auth_backend.settings import get_settings
from .logout import logout_router

settings = get_settings()

app = FastAPI()



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
# TODO tags fix

app.include_router(logout_router)
app.include_router(email_router := Email().router, prefix=email_router.prefix, tags=["Email"])
