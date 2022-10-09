from pydantic import BaseModel, EmailStr


class Email(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    token: str
