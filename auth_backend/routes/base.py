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


@app.exception_handler(ObjectNotFound)
async def not_found_handler(req, exc: ObjectNotFound):
    return PlainTextResponse(f"{exc}", status_code=404)


@app.exception_handler(IncorrectAuthType)
async def incorrect_auth_type_handler(req, exc: IncorrectAuthType):
    return PlainTextResponse(f"{exc}", status_code=403)


@app.exception_handler(AlreadyExists)
async def already_exists_handler(req, exc: AlreadyExists):
    return PlainTextResponse(f"{exc}", status_code=409)

@app.exception_handler(AuthFailed)
async def auth_failed_handler(req, exc: AuthFailed):
    return PlainTextResponse(status_code=401, content=exc.args[0])


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
# TODO tags fix

app.include_router(logout_router)
app.include_router(email_router := Email().router, prefix=email_router.prefix, tags=["Email"])
