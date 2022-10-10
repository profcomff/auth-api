from pydantic import EmailStr

from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.routes.models.base import Base, AuthModelsBase


class LoginPasswordPost(Base, AuthModelsBase):

    __represents__ = LoginPassword

    email: EmailStr
    password: str


class LoginPasswordPatch(Base, AuthModelsBase):

    __represents__ = LoginPassword

    email: EmailStr | None
    password: str | None