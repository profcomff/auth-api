import hashlib
import random
import string

from .auth_method import AuthMethod
from sqlalchemy.orm import Session
from auth_backend.models.db import UserSession
from .models.email import EmailPost


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class Email(AuthMethod):
    FIELDS = ["email", "hashed_password", "salt", "confirmed", "confirmation_token", "reset_token"]

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    async def login_flow(self, *, session: Session) -> UserSession:
        pass

    def __init__(self):
        super().__init__()

    async def register_flow(self, *, schema: EmailPost, session: Session, user_id: int | None = None, token: str | None = None) -> str:
        pass

    async def change_params(self):
        pass


