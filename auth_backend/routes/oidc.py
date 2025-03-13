import logging
from datetime import datetime
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Form, Header
from fastapi_sqlalchemy import db

from auth_backend.models.db import Scope, UserSession
from auth_backend.schemas.oidc import PostTokenResponse
from auth_backend.settings import get_settings
from auth_backend.utils.jwt import create_jwks
from auth_backend.utils.oidc_token import token_by_refresh_token, token_by_client_credentials


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
        "token_endpoint": f"{settings.APPLICATION_HOST}/openid/token",
        "userinfo_endpoint": f"{settings.APPLICATION_HOST}/me",
        "jwks_uri": f"{settings.APPLICATION_HOST}/.well-known/jwks",
        "scopes_supported": list(x[0] for x in db.session.query(Scope.name).all()),
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub", "iss", "exp", "iat"],
        "grant_types_supported": [
            "refresh_token",
            "client_credentials",
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
    user_agent: Annotated[str, Header()],
    grant_type: Annotated[Literal['refresh_token', 'client_credentials'], Form()],
    client_id: Annotated[str, Form()],  # Тут должна быть любая строка, которую проверяем в БД
    client_secret: Annotated[Optional[str], Form()] = None,
    scopes: Annotated[list[str] | None, Form()] = None,
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
        raise NotImplementedError("Only app client id supported")
    if grant_type == 'authorization_code':
        raise NotImplementedError("Authorization Code Flow not implemented yet")

    # Разные методы обмена токенов
    if grant_type == "refresh_token":
        new_session = await token_by_refresh_token(refresh_token, scopes)
    if grant_type == "refresh_token":
        new_session = await token_by_client_credentials(username, password, scopes, user_agent, background_tasks)

    return PostTokenResponse(
        access_token=new_session.token,
        token_type="Bearer",
        expires_in=int((new_session.expires - datetime.utcnow()).total_seconds()),
        refresh_token=new_session.token,
    )
