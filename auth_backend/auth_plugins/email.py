import hashlib
import random
import string

from fastapi import HTTPException, Header
from fastapi_sqlalchemy import db
from pydantic import validator, constr
from sqlalchemy import func

from auth_backend.base import Base, ResponseModel
from auth_backend.exceptions import AlreadyExists, AuthFailed, ObjectNotFound, SessionExpired, IncorrectUserAuthType
from auth_backend.models.db import AuthMethod
from auth_backend.models.db import UserSession, User
from auth_backend.settings import get_settings
from auth_backend.utils.smtp import (
    send_confirmation_email,
    send_change_password_confirmation,
    send_changes_password_notification,
)
from .auth_method import AuthMethodMeta, Session
from fastapi.background import BackgroundTasks

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


class RequestResetPassword(Base):
    password: str | None
    new_password: str | None


class ResetPassword(Base):
    new_password: constr(min_length=1)


def random_string(length: int = 12) -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(length)])


class Email(AuthMethodMeta):
    prefix = "/email"
    fields = [
        "email",
        "hashed_password",
        "salt",
        "confirmed",
        "confirmation_token",
        "tmp_email_confirmation_token",
        "tmp_email",
        "reset_token",
    ]

    def __init__(self):
        super().__init__()

        self.router.add_api_route("/approve", self._approve_email, methods=["GET"])
        self.router.add_api_route("/reset/email/request", self._request_reset_email, methods=["POST"])
        self.router.add_api_route("/reset/email/{user_id}", self._reset_email, methods=["GET"])
        self.router.add_api_route("/reset/password/{user_id}/request", self._request_reset_password, methods=["POST"])
        self.router.add_api_route("/reset/password/{user_id}", self._reset_password, methods=["POST"])
        self.router.prefix = self.prefix
        self.tags = ["Email"]

    @staticmethod
    async def _login(user_inp: EmailLogin) -> Session:
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
        if query.user.auth_methods.confirmed.value.lower() == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if query.user.auth_methods.email.value.lower() != user_inp.email.lower() or not Email._validate_password(
            user_inp.password, query.user.auth_methods.hashed_password.value, query.user.auth_methods.salt.value
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
        hashed_password = Email._hash_password(user_inp.password, salt)
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
        db.session.flush()

    @staticmethod
    async def _change_confirmation_link(user: User, confirmation_token: str) -> None:
        if user.auth_methods.confirmed.value == "true":
            raise AlreadyExists(User, user.id)
        else:
            user.auth_methods.confirmation_token.value = confirmation_token
            db.session.flush()

    @staticmethod
    async def _get_user_by_token_and_id(id: int, token: str) -> User:
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
    async def _register(
        user_inp: EmailRegister, background_tasks: BackgroundTasks, token: str = Header(default=None)
    ) -> ResponseModel:
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
            background_tasks.add_task(
                send_confirmation_email,
                to_addr=user_inp.email,
                link=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
            )
            return ResponseModel(status="Success", message="Email confirmation link sent")
        if user_inp.user_id and token:
            user = await Email._get_user_by_token_and_id(user_inp.user_id, token)
        else:
            user = User()
            db.session.add(user)
            db.session.flush()
        await Email._add_to_db(user_inp, confirmation_token, user)
        background_tasks.add_task(
            send_confirmation_email,
            to_addr=user_inp.email,
            link=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
        )
        raise HTTPException(
            status_code=201, detail=ResponseModel(status="Success", message="Email confirmation link sent").json()
        )

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    @staticmethod
    def _validate_password(password: str, hashed_password: str, salt: str) -> bool:
        """Проверяет, что хеш пароля совпадает с хешем из БД"""
        return Email._hash_password(password, salt) == hashed_password

    @staticmethod
    async def _approve_email(token: str) -> ResponseModel:
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
            raise HTTPException(status_code=403, detail=ResponseModel(status="Error", message="Incorrect link").json())
        auth_method.user.auth_methods.confirmed.value = True
        db.session.flush()
        return ResponseModel(status="Success", message="Email approved")

    @staticmethod
    async def _request_reset_email(
        scheme: EmailChange, background_tasks: BackgroundTasks, token: str = Header(min_length=1)
    ):
        session: UserSession = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
        if not session:
            raise HTTPException(
                status_code=404, detail=ResponseModel(status="Error", message="Session not found").json()
            )
        if session.expired:
            raise SessionExpired(token)
        if not hasattr(session.user.auth_methods, "email"):
            raise IncorrectUserAuthType()
        if session.user.auth_methods.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if session.user.auth_methods.email.value == scheme.email:
            raise HTTPException(status_code=401, detail=ResponseModel(status="Error", message="Email incorrect").json())
        tmp_email = AuthMethod(
            user_id=session.user_id, auth_method=Email.get_name(), param="tmp_email", value=scheme.email
        )
        token = random_string()
        tmp_email_confirmation_token = AuthMethod(
            user_id=session.user_id, auth_method=Email.get_name(), param="tmp_email_confirmation_token", value=token
        )
        db.session.add_all([tmp_email, tmp_email_confirmation_token])
        db.session.flush()
        background_tasks.add_task(
            send_confirmation_email,
            to_addr=scheme.email,
            link=f"{settings.APPLICATION_HOST}/email/reset/email/{session.user_id}?token={token}&email={scheme.email}",
        )
        return ResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    async def _reset_email(user_id: int, token: str, email: str):
        user: User = db.session.query(User).get(user_id)
        if user.auth_methods.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if email != user.auth_methods.tmp_email.value:
            raise HTTPException(
                status_code=403, detail=ResponseModel(status="Error", message="Incorrect new email").dict()
            )
        if token != user.auth_methods.tmp_email_confirmation_token.value:
            raise HTTPException(
                status_code=403, detail=ResponseModel(status="Error", message="Incorrect confirmation token").dict()
            )
        user.auth_methods.email.value = user.auth_methods.tmp_email.value
        db.session.delete(user.auth_methods.tmp_email_confirmation_token)
        db.session.delete(user.auth_methods.tmp_email)
        db.session.flush()
        return ResponseModel(status="Success", message="Email successfully changed")

    @staticmethod
    async def _request_reset_password(
        user_id: int, background_tasks: BackgroundTasks, schema: RequestResetPassword, token: str = Header(default=None)
    ):
        salt = random_string()
        if token and schema.new_password and schema.password:
            session: UserSession = db.session.query(UserSession).filter(UserSession.token == token).one_or_none()
            if not session:
                raise HTTPException(
                    status_code=403, detail=ResponseModel(status="Error", message="Session not found").json()
                )
            if session.expired:
                raise SessionExpired(token)
            if not session.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").json(),
                )
            if not Email._validate_password(
                schema.password, session.user.auth_methods.hashed_password.value, session.user.auth_methods.salt.value
            ):
                raise AuthFailed(error="Incorrect password")
            if user_id != session.user_id:
                raise HTTPException(
                    status_code=403, detail=ResponseModel(status="Error", message="Incorrect pair user_id+token").json()
                )
            session.user.auth_methods.hashed_password.value = Email._hash_password(schema.new_password, salt)
            session.user.auth_methods.salt.value = salt
            db.session.flush()
            background_tasks.add_task(send_changes_password_notification, session.user.auth_methods.email.value)
            return ResponseModel(status="Success", message="Password has been successfully changed")
        elif not token and not schema.password and not schema.new_password:
            user: User = db.session.query(User).get(user_id)
            if not user:
                raise ObjectNotFound(User, user_id)
            if not user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").json(),
                )
            if user.auth_methods.confirmed.value.lower() == "false":
                raise AuthFailed(
                    error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
                )
            db.session.add(
                AuthMethod(user_id=user_id, auth_method=Email.get_name(), param="reset_token", value=random_string())
            )
            db.session.flush()
            background_tasks.add_task(
                send_change_password_confirmation,
                user.auth_methods.email.value,
                f"{settings.APPLICATION_HOST}/email/reset?token={user.auth_methods.reset_token.value}",
            )
            return ResponseModel(status="Success", message="Reset link has been successfully mailed")
        raise HTTPException(
            status_code=422, detail=ResponseModel(status="Error", message="Unprocessable entity").json()
        )

    @staticmethod
    async def _reset_password(
        user_id: int, schema: ResetPassword, reset_token: str = Header(min_length=1)
    ) -> ResponseModel:
        user: User = db.session.query(User).get(user_id)
        if not user:
            raise ObjectNotFound(User, user_id)
        if not user.auth_methods.reset_token or user.auth_methods.reset_token.value != reset_token:
            raise HTTPException(
                status_code=403,
                detail=ResponseModel(status="Error", message="Incorrect reset_token").json(),
            )
        salt = random_string()
        user.auth_methods.hashed_password.value = Email._hash_password(schema.new_password, salt)
        user.auth_methods.salt.value = salt
        db.session.delete(user.auth_methods.reset_token)
        db.session.flush()
        return ResponseModel(status="Success", message="Password has been successfully changed")
