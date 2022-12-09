import hashlib
import random
import string

from fastapi import HTTPException, Header
from fastapi_sqlalchemy import db
from pydantic import validator, constr
from sqlalchemy import func
from starlette.responses import JSONResponse

from auth_backend.base import Base, ResponseModel
from auth_backend.exceptions import AlreadyExists, AuthFailed, ObjectNotFound, SessionExpired
from auth_backend.models.db import AuthMethod
from auth_backend.models.db import UserSession, User
from auth_backend.settings import get_settings
from auth_backend.utils.smtp import (
    send_confirmation_email,
    send_change_password_confirmation,
    send_changes_password_notification,
)
from .auth_method import AuthMethodMeta, Session

settings = get_settings()


def check_email(v):
    restricted: set[str] = {
        '"',
        '#',
        '&',
        "'",
        '(',
        ')',
        '*',
        ',',
        '/',
        ';',
        '<',
        '>',
        '?',
        '[',
        '\\',
        ']',
        '^',
        '`',
        '{',
        '|',
        '}',
        '~',
        '\n',
        '\r',
    }
    if "@" not in v:
        raise ValueError()
    if set(v) & restricted:
        raise ValueError()
    return v


class EmailLogin(Base):
    email: constr(min_length=1)
    password: constr(min_length=1)

    email_validator = validator("email", allow_reuse=True)(check_email)


class EmailRegister(EmailLogin):
    user_id: int | None


class EmailChange(Base):
    email: constr(min_length=1)

    email_validator = validator("email", allow_reuse=True)(check_email)


class ResetPassword(Base):
    password: constr(min_length=1) | None
    new_password: constr(min_length=1)


def random_string(length: int = 12) -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(length)])


class Email(AuthMethodMeta):
    prefix = "/email"
    fields = ["email", "hashed_password", "salt", "confirmed", "confirmation_token",
              "tmp_email_confirmation_token", "tmp_email", "reset_token"]

    def __init__(self):
        super().__init__()
        self.router.add_api_route("/approve", self.approve_email, methods=["GET"])
        self.router.add_api_route("/reset/email/request", self.request_reset_email, methods=["POST"])
        self.router.add_api_route("/reset/email/{user_id}", self.reset_email, methods=["GET"])
        self.router.add_api_route("/reset/password/{user_id}/request", self.request_reset_password, methods=["POST"])
        self.router.add_api_route("/reset/password", self.reset_password, methods=["GET"])
        self.router.prefix = self.prefix
        self.tags = ["Email"]

    @staticmethod
    async def login(user_inp: EmailLogin) -> Session:
        query = (
            db.session.query(AuthMethod)
                .filter(
                func.lower(AuthMethod.value) == user_inp.email.lower(),
                AuthMethod.param == "email",
                AuthMethod.auth_method == Email.get_name(),
            )
                .one_or_none()
        )
        if not query:
            raise AuthFailed(error="Incorrect login or password")
        if query.user.confirmed.value.lower() == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if query.user.email.value.lower() != user_inp.email.lower() or not Email.validate_password(
                user_inp.password, query.user.hashed_password.value, query.user.salt.value
        ):
            raise AuthFailed(error="Incorrect login or password")
        db.session.add(user_session := UserSession(user_id=query.user.id, token=random_string()))
        db.session.flush()
        return Session(
            user_id=user_session.user_id, token=user_session.token, id=user_session.id, expires=user_session.expires
        )

    @staticmethod
    async def _add_to_db(user_inp: EmailRegister, confirmation_token: str, user: User) -> None:
        salt = random_string()
        hashed_password = Email.hash_password(user_inp.password, salt)
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="email", value=user_inp.email))
        db.session.add(
            AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="hashed_password", value=hashed_password)
        )
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="salt", value=salt))
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="confirmed", value=str(False)))
        db.session.add(
            AuthMethod(
                user_id=user.id, auth_method=Email.get_name(), param="confirmation_token", value=confirmation_token
            )
        )
        db.session.add(AuthMethod(user_id=user.id, auth_method=Email.get_name(), param="reset_token", value=None))
        db.session.flush()
        return None

    @staticmethod
    async def _change_confirmation_link(user: User, confirmation_token: str):
        if user.confirmed.value == "true":
            raise AlreadyExists(User, user.id)
        else:
            user.confirmation_token.value = confirmation_token
            db.session.flush()

    @staticmethod
    async def _get_user_by_token_and_id(id: int, token: str) -> User | None:
        user: User = db.session.query(User).get(id)
        user_session: UserSession = (
            db.session.query(UserSession).filter(UserSession.token == token, UserSession.user_id == id).one_or_none()
        )
        if not user:
            raise ObjectNotFound(User, id)
        if not user_session:
            raise AuthFailed(error="Token not found, log in system")
        if user_session.expired:
            raise SessionExpired(user_session.token)
        return user

    @staticmethod
    async def register(user_inp: EmailRegister, token: str = Header(default=None)) -> ResponseModel | JSONResponse:
        confirmation_token: str = random_string()
        auth_method: AuthMethod = (
            db.session.query(AuthMethod)
                .filter(
                AuthMethod.param == "email",
                func.lower(AuthMethod.value) == user_inp.email.lower(),
                AuthMethod.auth_method == Email.get_name(),
            )
                .one_or_none()
        )
        if auth_method:
            await Email._change_confirmation_link(auth_method.user, confirmation_token)
            send_confirmation_email(
                to_addr=user_inp.email,
                link=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
            )
            return ResponseModel(status="Success", message="Email confirmation link sent")
        if user_inp.user_id and user_inp.token:
            user = await Email._get_user_by_token_and_id(user_inp.user_id, user_inp.token)
        else:
            user = User()
            db.session.add(user)
            db.session.flush()
        await Email._add_to_db(user_inp, confirmation_token, user)
        send_confirmation_email(
            to_addr=user_inp.email,
            link=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
        )
        return JSONResponse(
            status_code=201, content=ResponseModel(status="Success", message="Email confirmation link sent").json()
        )

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    @staticmethod
    def validate_password(password: str, hashed_password: str, salt: str):
        """Проверяет, что хеш пароля совпадает с хешем из БД"""
        return Email.hash_password(password, salt) == hashed_password

    @staticmethod
    async def approve_email(token: str) -> object:
        auth_method = (
            db.session.query(AuthMethod)
                .filter(
                AuthMethod.value == token,
                AuthMethod.param == "confirmation_token",
                AuthMethod.auth_method == Email.get_name(),
            )
                .one_or_none()
        )
        if not auth_method:
            return JSONResponse(status_code=403, content=ResponseModel(status="Error", message="Incorrect link").json())
        auth_method.user.confirmed.value = True
        db.session.flush()
        return ResponseModel(status="Success", message="Email approved")

    @staticmethod
    async def request_reset_email(scheme: EmailChange, token: str = Header(default=None)):
        if not token:
            raise HTTPException(status_code=400, detail=ResponseModel(status="Error", message="Header missing").json())
        session: UserSession = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
        if not session:
            raise HTTPException(
                status_code=404, detail=ResponseModel(status="Error", message="Session not found").json()
            )
        if session.expired:
            raise SessionExpired(token)
        if not hasattr(session.user, "email"):
            raise HTTPException(
                status_code=401,
                detail=ResponseModel(status="Error", message="Auth method restricted for this user").json(),
            )
        if session.user.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if session.user.email.value == scheme.email:
            raise HTTPException(status_code=401, detail=ResponseModel(status="Error", message="Email incorrect").json())
        if hasattr(session.user, "tmp_email_confirmation_token"):
            db.session.query(AuthMethod).filter(
                AuthMethod.user_id == session.user_id,
                AuthMethod.auth_method == Email.get_name(),
                AuthMethod.param == "tmp_email_confirmation_token",
            ).delete()
        if hasattr(session.user, "tmp_email"):
            db.session.query(AuthMethod).filter(
                AuthMethod.user_id == session.user_id,
                AuthMethod.auth_method == Email.get_name(),
                AuthMethod.param == "tmp_email",
            ).delete()
        tmp_email = AuthMethod(
            user_id=session.user_id, auth_method=Email.get_name(), param="tmp_email", value=scheme.email
        )
        token = random_string()
        tmp_email_confirmation_token = AuthMethod(
            user_id=session.user_id, auth_method=Email.get_name(), param="tmp_email_confirmation_token", value=token
        )
        db.session.add_all([tmp_email, tmp_email_confirmation_token])
        db.session.flush()
        send_confirmation_email(
            to_addr=scheme.email,
            link=f"{settings.APPLICATION_HOST}/email/reset/email/{session.user_id}?token={token}&email={scheme.email}",
        )
        return ResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    async def reset_email(user_id: int, token: str, email: str):
        user: User = db.session.query(User).get(user_id)
        if user.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if email != user.tmp_email.value:
            raise HTTPException(
                status_code=403, detail=ResponseModel(status="Error", message="Incorrect new email").dict()
            )
        if token != user.tmp_email_confirmation_token.value:
            raise HTTPException(
                status_code=403, detail=ResponseModel(status="Error", message="Incorrect confirmation token").dict()
            )
        user.email.value = user.tmp_email.value
        db.session.delete(user.tmp_email_confirmation_token)
        db.session.delete(user.tmp_email)
        db.session.flush()
        return ResponseModel(status="Success", message="Email successfully changed")

    @staticmethod
    async def request_reset_password(user_id: int, schema: ResetPassword, token: str = Header(default=None)):
        salt = random_string()
        if token:
            session: UserSession = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
            if not session:
                raise HTTPException(
                    status_code=404, detail=ResponseModel(status="Error", message="Session not found").json()
                )
            if session.expired:
                raise SessionExpired(token)
            if not hasattr(session.user.methods, "email"):
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").json(),
                )
            if not Email.validate_password(
                    schema.password, session.user.methods.email.hashed_password, session.user.methods.email.salt
            ):
                raise AuthFailed(error="Incorrect password")
            if user_id != session.user_id:
                raise HTTPException(
                    status_code=403, detail=ResponseModel(status="Error", message="Incorrect pair user_id+token").json()
                )
            session.user.hashed_password.value = Email.hash_password(schema.new_password, salt)
            session.user.salt.value = salt
            db.session.flush()
            send_changes_password_notification(session.user.methods.email.email)
            return ResponseModel(status="Success", message="Password has been successfully changed")
        else:
            user: User = db.session.query(User).get(user_id)
            if not user:
                raise ObjectNotFound(User, user_id)
            if not hasattr(user.methods, "email"):
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").json(),
                )
            user.reset_token.value = random_string()
            db.session.flush()
            send_change_password_confirmation(user.email.value,
                                              f"{settings.FRONTEND_HOST}/email/reset?token={user.reset_token.value}")
            return ResponseModel(status="Success", message="Reset link has been successfully mailed")

    @staticmethod
    async def reset_password(token: constr(min_length=1), password: constr(min_length=1)):
        pass
