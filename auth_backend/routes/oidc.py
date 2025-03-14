import logging
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, BackgroundTasks, Form, Header
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.email import Email
from auth_backend.exceptions import OidcGrantTypeClientNotSupported, OidcGrantTypeNotImplementedError
from auth_backend.models.db import Scope
from auth_backend.schemas.oidc import PostTokenResponse
from auth_backend.settings import get_settings
from auth_backend.utils.jwt import create_jwks
from auth_backend.utils.oidc_token import OidcGrantType, token_by_client_credentials, token_by_refresh_token


settings = get_settings()
router = APIRouter(prefix="/openid", tags=["OpenID"])
logger = logging.getLogger(__name__)


@router.get("/.well_known/openid_configuration")
def openid_configuration():
    """Конфигурация для подключения OpenID Connect совместимых приложений

    **Attention:** ручка соответствует спецификации не полностью, не все OIDC приложения смогут ей пользоваться
    """
    return {
        "issuer": f"{settings.APPLICATION_HOST}",
        "token_endpoint": f"{settings.APPLICATION_HOST}{settings.ROOT_PATH}/openid/token",
        "userinfo_endpoint": f"{settings.APPLICATION_HOST}{settings.ROOT_PATH}/me",
        "jwks_uri": f"{settings.APPLICATION_HOST}{settings.ROOT_PATH}/.well-known/jwks",
        "scopes_supported": list(x[0] for x in db.session.query(Scope.name).all()),
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "iss", "exp", "iat"],
        "grant_types_supported": [
            OidcGrantType.refresh_token,
            OidcGrantType.client_credentials,
        ],
    }


@router.get("/.well_known/jwks")
def jwks():
    """Публичные ключи для проверки JWT токенов"""
    return {"keys": [create_jwks()]}


@router.post("/token")
async def token(
    background_tasks: BackgroundTasks,
    # Общие OIDC параметры
    grant_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],  # Тут должна быть любая строка, которую проверяем в БД
    client_secret: Annotated[Optional[str], Form()] = None,
    scopes: Annotated[list[str] | None, Form()] = None,
    user_agent: Annotated[str | None, Header()] = None,
    # grant_type=refresh_token
    refresh_token: Annotated[Optional[str], Form()] = None,
    # grant_type=client_credentials
    username: Annotated[Optional[str], Form()] = None,
    password: Annotated[Optional[str], Form()] = None,
) -> PostTokenResponse:
    """Ручка для получения токена доступа

    ## Позволяет
    - Обменять старый не-JWT токен на новый c таким же набором доступов и таким же сроком давности
    - Обменять JWT токен на новый, если у него есть SESSION_UPDATE_SCOPE

    Потенциально будет позволять:
    - Обменивать Refresh Token на пару Access Token + Refresh Token
    - Обменивать Code (см. Oauth Authorization Code Flow) на пару Access Token + Refresh Token

    ## Параметры:
    Для всех запросов
    - `grant_type` – refresh_token/client_credentials (см. список в `/.well_known/openid_configuration` в поле `grant_types_supported`)
    - `client_id` – строка, по которой проверяется принадлежность к проекту (сейчас только app)
    - `scopes` – список прав для нового токена

    ### `grant_type=refresh_token`
    - refresh_token – токен, выданный этой ручкой или ручкой `/login` в методе авторизации

    ### `grant_type=client_credentials`
    - `username` – логин пользователя
    - `password` – пароль пользователя
    """
    scopes = scopes or []

    if client_id != 'app':
        raise OidcGrantTypeClientNotSupported(grant_type, client_id)
    if grant_type == OidcGrantType.authorization_code:
        raise OidcGrantTypeNotImplementedError("authorization_code")

    # Разные методы обмена токенов
    if grant_type == OidcGrantType.refresh_token:
        new_session = await token_by_refresh_token(refresh_token, scopes)
    elif grant_type == OidcGrantType.client_credentials and Email.is_active():
        new_session = await token_by_client_credentials(username, password, scopes, user_agent, background_tasks)
    else:
        raise OidcGrantTypeClientNotSupported(grant_type, client_id)

    return PostTokenResponse(
        access_token=new_session.token,
        token_type="Bearer",
        expires_in=int((new_session.expires - datetime.utcnow()).total_seconds()),
        refresh_token=new_session.token,
    )
