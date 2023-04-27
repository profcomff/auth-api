"""В этом файле находятся базовые способы аутентификации для приложений, не поддерживающих нашу
библиотеку аутентификации auth-lib.
"""
import logging

from typing import Annotated

from fastapi import Depends, APIRouter
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from auth_backend.auth_plugins.email import Email, EmailLogin, AuthFailed


app_auth = APIRouter(include_in_schema=False)
security = HTTPBasic()
logger = logging.getLogger(__name__)


@app_auth.get("/basic/{scope}")
async def read_current_user(credentials: Annotated[HTTPBasicCredentials, Depends(security)], scope: str):
    """Basic Auth implemented for NextCloud

    Authenticate users by an HTTP Basic access authentication call. HTTP server of your choice to
    authenticate. It should return HTTP 2xx for correct credentials and an appropriate other error
    code for wrong ones or refused access. The HTTP server must respond to any requests to the
    target URL with the "www-authenticate" header set. Otherwise BasicAuth considers itself to be
    misconfigured or the HTTP server unfit for authentication.

    More: https://github.com/nextcloud/user_external#basicauth
    """
    logger.debug(dict(email=credentials.username, password=credentials.password))
    try:
        session = await Email._login(EmailLogin(
            email=credentials.username,
            password=credentials.password,
        ))
        logger.debug(session)
        if scope not in session.session_scopes:
            return PlainTextResponse("Unauthorized", 401, {"WWW-Authenticate": "Basic"})
        return PlainTextResponse("Ok", 200, {"WWW-Authenticate": "Basic {session.token}"})
    except AuthFailed as exc:
        logger.debug(exc)
        return PlainTextResponse("Not authenticated", 403, {"WWW-Authenticate": "Basic"})
    except Exception as exc:
        logger.error(exc)
        return PlainTextResponse("Not authenticated", 500, {"WWW-Authenticate": "Basic"})
