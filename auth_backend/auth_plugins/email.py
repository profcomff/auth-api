import hashlib
import random
import string
from uuid import uuid4

from fastapi_sqlalchemy import db
from starlette.responses import PlainTextResponse

from auth_backend.exceptions import AlreadyExists, AuthFailed, ObjectNotFound
from auth_backend.models.db import AuthMethod
from auth_backend.models.db import UserSession, User
from .auth_method import AuthMethodMeta
from .models.email import EmailPost
from .smtp import send_confirmation_email
from auth_backend.settings import get_settings
from .models.base import Session

settings = get_settings()


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class Email(AuthMethodMeta):
    prefix = "/email"

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/approve", self.approve_email, methods=["GET"])
        self.router.prefix = self.prefix
        self.tags = ["Email"]

    @staticmethod
    async def login(schema: EmailPost) -> Session:
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
        db.session.add(user_session := UserSession(user_id=query.user.id, token=str(uuid4())))
        db.session.flush()
        return Session(user_id=user_session.user_id, token=user_session.token, id=user_session.id,
                       expires=user_session.expires)

    @staticmethod
    async def registrate(schema: EmailPost, user_id: int | None = None, token: str | None = None) -> PlainTextResponse:
        confirmation_token: str = str(uuid4())
        query: AuthMethod = db.session.query(AuthMethod).filter(AuthMethod.param == "email",
                                                                AuthMethod.value == schema.email,
                                                                AuthMethod.auth_method == Email.get_name()).one_or_none()
        if query:
            secrets = {row.param: row.value for row in query.user.get_method_secrets(Email.get_name())}
            if secrets.get("confirmed") == "true":
                raise AlreadyExists(User, query.user_id)
            else:
                for row in query.user.get_method_secrets(Email.get_name()):
                    row.value = confirmation_token if row.param == "confirmation_token" else row.value
                db.session.flush()
                send_confirmation_email(subject="Повторное подтверждение регистрации Твой ФФ!", to_addr=schema.email,
                                        link=f"{settings.HOST}/email/approve?token={confirmation_token}")
                return PlainTextResponse(status_code=200, content="Check email")
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
        hashed_password = f"{salt}${hashed_password}"
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="email", value=schema.email))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="hashed_password",
                                  value=hashed_password))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="salt", value=salt))
        db.session.add(
            AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="confirmed", value=str(False)))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="confirmation_token",
                                  value=confirmation_token))
        db.session.add(
            AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="reset_token", value=None))
        db.session.flush()
        send_confirmation_email(subject="Подтверждение регистрации Твой ФФ!", to_addr=schema.email,
                                link=f"{settings.HOST}/email/approve?token={confirmation_token}")
        return PlainTextResponse(status_code=201, content="Check email")

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    @staticmethod
    def validate_password(password: str, hashed_password: str):
        """ Проверяет, что хеш пароля совпадает с хешем из БД """
        salt, hashed = hashed_password.split("$")
        return Email.hash_password(password, salt) == hashed

    @staticmethod
    async def approve_email(token: str) -> object:
        query = db.session.query(AuthMethod).filter(AuthMethod.value == token, AuthMethod.param == "confirmation_token",
                                                    AuthMethod.auth_method == Email.get_name()).one_or_none()
        if not query:
            return PlainTextResponse(status_code=403, content="Incorrect link")
        for row in query.user.get_method_secrets(Email.get_name()):
            if row.param == "confirmed":
                row.value = True
        db.session.flush()
        return PlainTextResponse(status_code=200, content="Email approved")

    async def change_params(self):
        pass
