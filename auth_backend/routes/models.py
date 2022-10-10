import datetime

from pydantic import BaseModel, EmailStr


class Base(BaseModel):
    def __repr__(self) -> str:
        attrs = []
        for k, v in self.__class__.schema().items():
            attrs.append(f"{k}={v}")
        return "{}({})".format(self.__class__.__name__, ', '.join(attrs))


class Email(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    token: str


class Session(Token):
    expires: datetime.datetime
    id: int
    user_id: int
