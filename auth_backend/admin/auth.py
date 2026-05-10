from fastapi import Request
from sqladmin.authentication import AuthenticationBackend

from auth_backend.settings import get_settings


settings = get_settings()


class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        if username == settings.ADMIN_LOGIN and password == settings.ADMIN_PASSWORD:
            request.session["user"] = username
            return True
        return False

    async def logout(self, request: Request) -> bool:
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        user = request.session.get("user")
        return user is not None
