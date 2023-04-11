import starlette.requests
from starlette.responses import JSONResponse

from auth_backend.base import Logout
from auth_backend.exceptions import (
    AlreadyExists,
    AuthFailed,
    IncorrectUserAuthType,
    OauthAuthFailed,
    OauthCredentialsIncorrect,
    ObjectNotFound,
    SessionExpired,
)

from .base import app


@app.exception_handler(ObjectNotFound)
async def not_found_handler(req: starlette.requests.Request, exc: ObjectNotFound):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=404)


@app.exception_handler(IncorrectUserAuthType)
async def incorrect_auth_type_handler(req: starlette.requests.Request, exc: IncorrectUserAuthType):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=403)


@app.exception_handler(AlreadyExists)
async def already_exists_handler(req: starlette.requests.Request, exc: AlreadyExists):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=409)


@app.exception_handler(AuthFailed)
async def auth_failed_handler(req: starlette.requests.Request, exc: AuthFailed):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=401)


class OauthAuthFailedResponseModel(Logout):
    id_token: str | None


@app.exception_handler(OauthAuthFailed)
async def oauth_failed_handler(req: starlette.requests.Request, exc: OauthAuthFailed):
    return JSONResponse(
        content=OauthAuthFailedResponseModel(
            status="Error",
            message=f"{exc}",
            id_token=exc.id_token,
        ).dict(exclude_none=True),
        status_code=exc.status_code,
    )


@app.exception_handler(OauthCredentialsIncorrect)
async def oauth_creds_failed_handler(req: starlette.requests.Request, exc: OauthCredentialsIncorrect):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=406)


@app.exception_handler(SessionExpired)
async def session_expired_handler(req: starlette.requests.Request, exc: SessionExpired):
    return JSONResponse(content=Logout(status="Error", message=f"{exc}").dict(), status_code=403)


@app.exception_handler(Exception)
async def http_error_handler(req: starlette.requests.Request, exc: Exception):
    return JSONResponse(content=Logout(status="Error", message="Internal server error").dict(), status_code=500)
