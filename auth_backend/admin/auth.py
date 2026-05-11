from fastapi import Request
from sqladmin.authentication import AuthenticationBackend

from auth_backend.settings import get_settings
from auth_backend.utils.security import UnionAuth
from auth_lib.methods import AuthLib

settings = get_settings()

class AdminAuth(AuthenticationBackend):

    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = form.get("username")
        token = form.get("password")
        if username != settings.ADMIN_LOGIN:
            return False
        valid = await self._is_valid_token(token)
        if valid:
            request.session["token"] = token
            return True
        else:
            return False

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")
        if not token:
            return False
        return await self._is_valid_token(token)

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    @staticmethod
    async def _is_valid_token(token: str) -> bool:
        try:
            result = AuthLib(auth_url=settings.AUTH_URL).check_token(token)
            if not result:
                return False
            session_scopes = {
                scope["name"].lower() for scope in result.get("session_scopes", [])
            }
            required_scopes = "auth.sqladmin.admin"
            if required_scopes not in session_scopes:
                return False
            return True
        except Exception:
            return False