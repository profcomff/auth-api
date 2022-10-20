import hashlib
import random
import string

from fastapi import APIRouter

from .auth_method import AuthMethodMeta
from fastapi_sqlalchemy import db
from sqlalchemy.orm import Session
from auth_backend.models.db import UserSession, User
from .models.email import EmailPost
from auth_backend.models.db import AuthMethod
from auth_backend.exceptions import AlreadyExists, AuthFailed, ObjectNotFound
from uuid import uuid4


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class Email(AuthMethodMeta):



    def __init__(self):
        super().__init__()
        self.router.prefix = f"/{Email.get_name()}"
        self.tags = ["Email"]

    @staticmethod
    async def login(schema: EmailPost) -> UserSession:
        query = db.session.query(AuthMethod).filter(AuthMethod.value == schema.email, AuthMethod.param == "email",
                                                    AuthMethod.auth_method == Email.get_name()).one_or_none()
        if not query:
            raise AuthFailed(error="Incorrect login or password")
        secrets = {row.param: row.value for row in query.user.get_method_secrets(Email.get_name())}
        if not secrets.get("confirmed"):
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email")
        if secrets.get("email") != schema.email or not Email.validate_password(schema.password,
                                                                               secrets.get("hashed_password")):
            raise AuthFailed(error="Incorrect login or password")
        db.session.add(usef_session := UserSession(user_id=query.user.id, token=str(uuid4())))
        db.session.flush()
        return usef_session

    @staticmethod
    async def registrate(schema: EmailPost, user_id: int, token: str) -> object:
        confirmation_token: str = str(uuid4())
        query: AuthMethod = db.session.query(AuthMethod).filter(AuthMethod.param == "email",
                                                                AuthMethod.value == schema.email,
                                                                AuthMethod.auth_method == Email.get_name()).one_or_none()
        if query:
            secrets = {row.param: row.value for row in query.user.get_method_secrets(Email.get_name())}
            if secrets.get("confirmed") == "true":
                raise AlreadyExists(User, query.user_id)
            else:
                for row in query.user.get_method_secrets(Email.__name__):
                    row.value = confirmation_token if row.param == "confirmation_token" else row.value
                db.session.flush()
                return str(confirmation_token)
        if user_id and token:
            user: User = db.session.query(User).get(user_id)
            user_session: UserSession = db.session.query(UserSession).filter(UserSession.token == token,
                                                                             UserSession.user_id == user_id).one_or_none()
            if not user:
                raise ObjectNotFound(User, user_id)
            if not user_session:
                raise AuthFailed(error="Token not found, log in system")
            if user_session.expired:
                raise AuthFailed(error="Session expired, log in system again")
        else:
            db.session.add(user := User())
            db.session.flush()
        salt = get_salt()
        hashed_password = Email.hash_password(schema.password, salt)
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="email", value=schema.email))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="hashed_password",
                                  value=hashed_password))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="aslt", value=salt))
        db.session.add(
            AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="confirmed", value=str(False)))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="confirmation_token",
                                  value=confirmation_token))
        db.session.add(
            AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="reset_token", value=None))
        db.session.flush()
        return str(confirmation_token)

    FIELDS = ["email", "hashed_password", "salt", "confirmed", "confirmation_token", "reset_token"]

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    @staticmethod
    def validate_password(password: str, hashed_password: str):
        """ Проверяет, что хеш пароля совпадает с хешем из БД """
        salt, hashed = hashed_password.split("$")
        return Email.hash_password(password, salt) == hashed

    async def login_flow(self, *, schema: EmailPost, session: Session) -> UserSession:
        pass

    async def register_flow(self, *, schema: EmailPost, session: Session, user_id: int | None = None,
                            token: str | None = None) -> str:
        pass

    async def change_params(self):
        pass
