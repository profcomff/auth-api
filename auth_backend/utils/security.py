from fastapi.exceptions import HTTPException
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.base import SecurityBase
from fastapi_sqlalchemy import db
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

from auth_backend.models.db import UserSession


class UnionAuth(SecurityBase):
    model = APIKey.construct(in_=APIKeyIn.header, name="Authorization")
    scheme_name = "token"
    auto_error: bool
    allow_none: bool
    _scopes: list[str] = []

    def __init__(self, scopes: list[str], allow_none=False, auto_error=False) -> None:
        super().__init__()
        self.auto_error = auto_error
        self.allow_none = allow_none
        self._scopes = scopes

    def _except(self):
        if self.auto_error:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
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
        if len(
            set([_scope.lower() for _scope in self._scopes])
            & set([scope.name.lower() for scope in user_session.scopes])
        ) != len(set(self._scopes)):
            self._except()
        return user_session
