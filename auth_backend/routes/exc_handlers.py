import starlette.requests
from starlette.responses import JSONResponse

from auth_backend.base import StatusResponseModel
from auth_backend.exceptions import (
    AlreadyExists,
    AuthFailed,
    IncorrectUserAuthType,
    LastAuthMethodDelete,
    OauthAuthFailed,
    OauthCredentialsIncorrect,
    ObjectNotFound,
    OidcGrantTypeClientNotSupported,
    OidcGrantTypeNotImplementedError,
    SessionExpired,
    TooManyEmailRequests,
)

from .base import app


@app.exception_handler(ObjectNotFound)
async def not_found_handler(req: starlette.requests.Request, exc: ObjectNotFound):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=404
    )


@app.exception_handler(IncorrectUserAuthType)
async def incorrect_auth_type_handler(req: starlette.requests.Request, exc: IncorrectUserAuthType):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=403
    )


@app.exception_handler(AlreadyExists)
async def already_exists_handler(req: starlette.requests.Request, exc: AlreadyExists):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=409
    )


@app.exception_handler(AuthFailed)
async def auth_failed_handler(req: starlette.requests.Request, exc: AuthFailed):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=401
    )


class OauthAuthFailedStatusResponseModel(StatusResponseModel):
    id_token: str | None = None


@app.exception_handler(OauthAuthFailed)
async def oauth_failed_handler(req: starlette.requests.Request, exc: OauthAuthFailed):
    return JSONResponse(
        content=OauthAuthFailedStatusResponseModel(
            status="Error",
            message=exc.eng,
            ru=exc.ru,
            id_token=exc.id_token,
        ).model_dump(exclude_none=True),
        status_code=exc.status_code,
    )


@app.exception_handler(OauthCredentialsIncorrect)
async def oauth_creds_failed_handler(req: starlette.requests.Request, exc: OauthCredentialsIncorrect):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=406
    )


@app.exception_handler(SessionExpired)
async def session_expired_handler(req: starlette.requests.Request, exc: SessionExpired):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(), status_code=403
    )


@app.exception_handler(TooManyEmailRequests)
async def too_many_requests_handler(req: starlette.requests.Request, exc: TooManyEmailRequests):
    return JSONResponse(
        content=StatusResponseModel(
            status="Error",
            message=exc.eng,
            ru=exc.ru,
        ).model_dump(),
        status_code=429,
    )


@app.exception_handler(LastAuthMethodDelete)
async def last_auth_method_delete_handler(req: starlette.requests.Request, exc: LastAuthMethodDelete):
    return JSONResponse(
        content=StatusResponseModel(
            status="Error",
            message=exc.eng,
            ru=exc.ru,
        ).model_dump(),
        status_code=403,
    )


@app.exception_handler(
    OidcGrantTypeClientNotSupported,
)
async def oidc_grant_type_client_not_supported_handler(req: starlette.requests.Request, exc: Exception):
    return JSONResponse(
        StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(),
        status_code=400,
    )


@app.exception_handler(OidcGrantTypeNotImplementedError)
async def oidc_grant_type_not_implemented_error_handler(req: starlette.requests.Request, exc: Exception):
    return JSONResponse(
        StatusResponseModel(status="Error", message=exc.eng, ru=exc.ru).model_dump(),
        status_code=400,
    )


@app.exception_handler(Exception)
async def http_error_handler(req: starlette.requests.Request, exc: Exception):
    return JSONResponse(
        content=StatusResponseModel(status="Error", message="Internal server error", ru="Ошибка").model_dump(),
        status_code=500,
    )
