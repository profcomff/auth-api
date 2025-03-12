import logging
from datetime import datetime
from typing import Literal, Annotated, Optional

from fastapi import APIRouter, Depends, Form
from fastapi_sqlalchemy import db
from pydantic import AnyHttpUrl, BaseModel

from auth_backend.exceptions import SessionExpired
from auth_backend.models.db import Scope, UserSession
from auth_backend.settings import get_settings
from auth_backend.utils.jwt import create_jwks
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.user_session_control import SESSION_UPDATE_SCOPE, create_session

settings = get_settings()
router = APIRouter(prefix="/openid", tags=["OpenID"])
logger = logging.getLogger(__name__)


class PostTokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: str


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
        # "authorization_endpoint": f"{settings.APPLICATION_HOST}/auth",
    }


@router.get("/.well_known/jwks")
def jwks():
    """Публичные ключи для проверки JWT токенов"""
    return {"keys": [create_jwks()]}


@router.post("/token")
async def token(
    grant_type: Annotated[Literal['refresh_token'], Form()],
    client_id: Annotated[Literal['app'], Form()],  # Тут должна быть любая строка, которую проверяем в БД
    client_secret: Annotated[Optional[str], Form()] = None,
    refresh_token: Annotated[Optional[str], Form()] = None,
) -> PostTokenResponse:
    """Ручка для получения токена доступа

    Позволяет:
    - Обменять старый не-JWT токен на новый c таким же набором доступов и таким же сроком давности
    - Обменять JWT токен на новый, если у него есть SESSION_UPDATE_SCOPE

    Потенциально будет позволять:
    - Обменивать Refresh Token на пару Access Token + Refresh Token
    - Обменивать Code (см. Oauth Authorization Code Flow) на пару Access Token + Refresh Token
    """
    if grant_type == 'authorization_code':
        raise NotImplementedError("Authorization Code Flow not implemented yet")
    if grant_type == "refresh_token":
        # Все токены автоматически считаем refresh-токенами
        if not refresh_token:
            raise TypeError("refresh_token required for refresh_token grant_type ")
        old_session: UserSession = (
            UserSession.query(session=db.session).filter(UserSession.token == refresh_token).one_or_none()
        )
        if not old_session or old_session.expired:
            raise SessionExpired()

        # Продлеваем только те токены, которые явно разрешено продлевать
        # Остальные просто заменяем на новые с тем же сроком действия
        session_scopes = old_session.user.scope_names if old_session.is_unbounded else old_session.scope_names
        expire_ts = None
        if SESSION_UPDATE_SCOPE not in session_scopes:
            expire_ts = old_session.expires

        new_session = await create_session(
            old_session.user,
            session_scopes,
            expire_ts,
            old_session.session_name,
            old_session.is_unbounded,
            db_session=db.session,
        )

        # Старую сессию убиваем
        old_session.expires = datetime.utcnow()
        db.session.commit()

        return PostTokenResponse(
            access_token=new_session.token,
            token_type="Bearer",
            expires_in=int((new_session.expires - datetime.utcnow()).total_seconds()),
            refresh_token=new_session.token,
        )
