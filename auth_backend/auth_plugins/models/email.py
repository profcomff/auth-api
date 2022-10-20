from pydantic import BaseModel, EmailStr


class EmailPost(BaseModel):
    email: EmailStr
    password: str
