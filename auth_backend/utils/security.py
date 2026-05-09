import datetime

from fastapi.exceptions import HTTPException
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.base import SecurityBase
from fastapi_sqlalchemy import db
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

from auth_backend.models.db import UserSession
from auth_backend.settings import get_settings
from auth_backend.utils.user_session_basics import session_expires_date
from auth_backend.utils.user_session_control import SESSION_UPDATE_SCOPE


settings = get_settings()


class UnionAuth(SecurityBase):
    '''Проверяет токен, возвращает пользователя.

    Основной метод находится в `__call__`
    '''

    model = APIKey.model_construct(in_=APIKeyIn.header, name="Authorization")
    scheme_name = "token"
    auto_error: bool
    allow_none: bool
    _scopes: list[str] = []

    def __init__(self, scopes: list[str] = None, allow_none=False, auto_error=False) -> None:
        super().__init__()
        self.auto_error = auto_error
        self.allow_none = allow_none
        self._scopes = scopes or []

    def _except(self):
        if self.auto_error:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authorized")
        else:
            return None

    async def __call__(
        self,
        request: Request,
    ) -> UserSession:
        token = request.headers.get("Authorization")
        if not token and self.allow_none:
            return None
        if not token:
            return self._except()
        user_session: UserSession = (
            UserSession.query(session=db.session).filter(UserSession.token == token).one_or_none()
        )
        if not user_session:
            self._except()
        user_session.last_activity = datetime.datetime.utcnow()

        if user_session.expired:
            self._except()
        session_scopes = user_session.user.scope_names if user_session.is_unbounded else user_session.scope_names
        if not settings.JWT_ENABLED and SESSION_UPDATE_SCOPE in session_scopes:
            user_session.expires = session_expires_date()
        db.session.commit()
        if len(set([_scope.lower() for _scope in self._scopes]) & session_scopes) != len(set(self._scopes)):
            self._except()
        return user_session
