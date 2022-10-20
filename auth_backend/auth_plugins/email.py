import hashlib
import random
import string

from .auth_method import AuthMethodMeta
from sqlalchemy.orm import Session
from auth_backend.models.db import UserSession
from .models.email import EmailPost
from auth_backend.models.db import AuthMethod


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class Email(AuthMethodMeta):
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
        query = session.query(AuthMethod).filter(AuthMethod.param == "email", AuthMethod.value == schema.email, AuthMethod.auth_method == Email.get_name()).one_or_none()
        if query:
            secrets = {row.param: row.value for row in query.user.get_method_secrets(Email.get_name())}
            if secrets.get("confirmed") == "true":
                pass


    async def change_params(self):
        pass


