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
    auth_url: str

    def __init__(self, auth_url: str = "", auto_error=True) -> None:
        super().__init__()
        self.auto_error = auto_error
        self.auth_url = auth_url

    def _except(self):
        if self.auto_error:
            raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Not authenticated")
        else:
            return {}

    async def __call__(
        self,
        request: Request,
    ) -> dict[str, str | int]:
        token = request.headers.get("Authorization")
        if not token:
            return self._except()
        user_session: UserSession = (
            UserSession.get_all(session=db.session).filter(UserSession.token == token).one_or_none()
        )
        if not user_session:
            self._except()
        return {"id": user_session.user_id, "email": user_session.user.auth_methods.email.value}
