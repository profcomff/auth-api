import starlette.requests
from starlette.responses import JSONResponse

from auth_backend.exceptions import ObjectNotFound, IncorrectAuthType, AlreadyExists, AuthFailed, SessionExpired
from .base import app
from auth_backend.base import ResponseModel


@app.exception_handler(ObjectNotFound)
async def not_found_handler(req: starlette.requests.Request, exc: ObjectNotFound):
    return JSONResponse(content=ResponseModel(status="Error", message=f"{exc}").dict(), status_code=404)


@app.exception_handler(IncorrectAuthType)
async def incorrect_auth_type_handler(req: starlette.requests.Request, exc: IncorrectAuthType):
    return JSONResponse(content=ResponseModel(status="Error", message=f"{exc}").dict(), status_code=403)


@app.exception_handler(AlreadyExists)
async def already_exists_handler(req: starlette.requests.Request, exc: AlreadyExists):
    return JSONResponse(content=ResponseModel(status="Error", message=f"{exc}").dict(), status_code=409)


@app.exception_handler(AuthFailed)
async def auth_failed_handler(req: starlette.requests.Request, exc: AuthFailed):
    return JSONResponse(content=ResponseModel(status="Error", message=f"{exc}").dict(), status_code=401)


@app.exception_handler(SessionExpired)
async def session_expired_handler(req: starlette.requests.Request, exc: SessionExpired):
    return JSONResponse(content=ResponseModel(status="Error", message=f"{exc}").dict(), status_code=403)


@app.exception_handler(Exception)
async def http_error_handler(req: starlette.requests.Request, exc: Exception):
    return JSONResponse(content=ResponseModel(status="Error", message="Internal server error").dict(), status_code=500)
