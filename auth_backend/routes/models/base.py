import datetime

from pydantic import BaseModel, EmailStr
from auth_backend.auth_plugins.login_password import LoginPassword
from auth_backend.auth_plugins.auth_interface import AuthInterface


class Base(BaseModel):
    def __repr__(self) -> str:
        attrs = []
        for k, v in self.__class__.schema().items():
            attrs.append(f"{k}={v}")
        return "{}({})".format(self.__class__.__name__, ', '.join(attrs))


class AuthModelsBase:
    __represents__: AuthInterface

    def represents_check(self, v: object) -> bool:
        if self.__represents__ is not v:
            return False
        return True

class Token(Base):
    token: str


class Session(Token):
    expires: datetime.datetime
    id: int
    user_id: int
