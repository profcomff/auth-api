import logging

from fastapi import APIRouter
from fastapi_sqlalchemy import db

from auth_backend.models.db import Scope
from auth_backend.settings import get_settings
from auth_backend.utils.jwt import create_jwks


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
        # "authorization_endpoint": f"{settings.APPLICATION_HOST}/auth",
    }


@router.get("/.well_known/jwks")
def jwks():
    return {"keys": [create_jwks()]}
