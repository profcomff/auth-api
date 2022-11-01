from pydantic import EmailStr

from .base import Base


class EmailPost(Base):
    email: EmailStr
    password: str
