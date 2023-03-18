import hashlib

from fastapi import Depends, Header, HTTPException
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import constr, validator
from sqlalchemy import func

from auth_backend.base import Base, ResponseModel
from auth_backend.exceptions import AlreadyExists, AuthFailed, IncorrectUserAuthType, SessionExpired
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.settings import get_settings
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.smtp import (
    send_change_password_confirmation,
    send_changes_password_notification,
    send_confirmation_email,
    send_reset_email,
)
from .auth_method import AuthMethodMeta, Session, random_string
from auth_backend.schemas.types.scopes import Scope

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
    scopes: list[Scope] | None

    email_validator = validator("email", allow_reuse=True)(check_email)


class EmailRegister(Base):
    email: constr(min_length=1)
    password: constr(min_length=1)

    email_validator = validator("email", allow_reuse=True)(check_email)


class EmailChange(Base):
    email: constr(min_length=1)

    email_validator = validator("email", allow_reuse=True)(check_email)


class RequestResetPassword(Base):
    email: constr(min_length=1)
    password: str | None
    new_password: str | None

    email_validator = validator("email", allow_reuse=True)(check_email)


class ResetPassword(Base):
    email: constr(min_length=1)
    new_password: constr(min_length=1)

    email_validator = validator("email", allow_reuse=True)(check_email)


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

        self.router.add_api_route("/approve", self._approve_email, methods=["GET"], response_model=ResponseModel)
        self.router.add_api_route(
            "/reset/email/request", self._request_reset_email, methods=["POST"], response_model=ResponseModel
        )
        self.router.add_api_route("/reset/email", self._reset_email, methods=["GET"], response_model=ResponseModel)
        self.router.add_api_route(
            "/reset/password/request", self._request_reset_password, methods=["POST"], response_model=ResponseModel
        )
        self.router.add_api_route(
            "/reset/password", self._reset_password, methods=["POST"], response_model=ResponseModel
        )
        self.tags = ["Email"]

    @classmethod
    async def _login(cls, user_inp: EmailLogin) -> Session:
        query = (
            AuthMethod.query(session=db.session)
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
        return await cls._create_session(query.user, user_inp.scopes, db_session=db.session)

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

    @classmethod
    async def _register(
        cls,
        user_inp: EmailRegister,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> ResponseModel:
        confirmation_token: str = random_string()
        auth_method: AuthMethod = (
            AuthMethod.query(session=db.session)
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
            db.session.commit()
            return ResponseModel(status="Success", message="Email confirmation link sent")
        if user_session:
            user = await cls._get_user(user_session=user_session, db_session=db.session)
            if not user:
                raise SessionExpired(user_session.token)
        else:
            user = await cls._create_user(db_session=db.session)
        await Email._add_to_db(user_inp, confirmation_token, user)
        background_tasks.add_task(
            send_confirmation_email,
            to_addr=user_inp.email,
            link=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
        )
        db.session.commit()
        return ResponseModel(status="Success", message="Email confirmation link sent")

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
            AuthMethod.query(session=db.session)
            .filter(
                AuthMethod.value == token,
                AuthMethod.param == "confirmation_token",
                AuthMethod.auth_method == Email.get_name(),
            )
            .one_or_none()
        )
        if not auth_method:
            raise HTTPException(status_code=403, detail=ResponseModel(status="Error", message="Incorrect link").dict())
        auth_method.user.auth_methods.confirmed.value = "true"
        db.session.commit()
        return ResponseModel(status="Success", message="Email approved")

    @staticmethod
    async def _request_reset_email(
        scheme: EmailChange,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    ) -> ResponseModel:
        if user_session.expired:
            raise SessionExpired(user_session.token)
        if not user_session.user.auth_methods.email:
            raise IncorrectUserAuthType()
        if user_session.user.auth_methods.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if user_session.user.auth_methods.email.value == scheme.email:
            raise HTTPException(status_code=401, detail=ResponseModel(status="Error", message="Email incorrect").dict())
        tmp_email = AuthMethod(
            user_id=user_session.user_id, auth_method=Email.get_name(), param="tmp_email", value=scheme.email
        )
        token = random_string()
        tmp_email_confirmation_token = AuthMethod(
            user_id=user_session.user_id,
            auth_method=Email.get_name(),
            param="tmp_email_confirmation_token",
            value=token,
        )
        db.session.add_all([tmp_email, tmp_email_confirmation_token])
        background_tasks.add_task(
            send_reset_email,
            to_addr=scheme.email,
            link=f"{settings.APPLICATION_HOST}/email/reset/email/{user_session.user_id}?token={token}&email={scheme.email}",
        )
        db.session.commit()
        return ResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    async def _reset_email(token: str) -> ResponseModel:
        auth: AuthMethod = (
            AuthMethod.query(session=db.session)
            .filter(
                AuthMethod.param == 'tmp_email_confirmation_token',
                AuthMethod.value == token,
            )
            .one_or_none()
        )
        if not auth:
            raise HTTPException(
                status_code=403, detail=ResponseModel(status="Error", message="Incorrect confirmation token").dict()
            )
        user: User = auth.user
        if user.auth_methods.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        user.auth_methods.email.value = user.auth_methods.tmp_email.value
        user.auth_methods.tmp_email_confirmation_token.is_deleted = True
        user.auth_methods.tmp_email.is_deleted = True
        db.session.commit()
        return ResponseModel(status="Success", message="Email successfully changed")

    @staticmethod
    async def _request_reset_password(
        schema: RequestResetPassword,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> ResponseModel:
        salt = random_string()
        if user_session and schema.new_password and schema.password:
            if user_session.expired:
                raise SessionExpired(user_session.token)
            if not user_session.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").dict(),
                )
            if not Email._validate_password(
                schema.password,
                user_session.user.auth_methods.hashed_password.value,
                user_session.user.auth_methods.salt.value,
            ):
                raise AuthFailed(error="Incorrect password")
            auth_method_email: AuthMethod = (
                AuthMethod.query(session=db.session)
                .filter(
                    AuthMethod.auth_method == Email.get_name(),
                    AuthMethod.param == "email",
                    AuthMethod.value == schema.email,
                )
                .one_or_none()
            )
            if auth_method_email.user_id != user_session.user_id:
                raise HTTPException(
                    status_code=403, detail=ResponseModel(status="Error", message="Incorrect user session").dict()
                )
            user_session.user.auth_methods.hashed_password.value = Email._hash_password(schema.new_password, salt)
            user_session.user.auth_methods.salt.value = salt
            background_tasks.add_task(send_changes_password_notification, user_session.user.auth_methods.email.value)
            db.session.commit()
            return ResponseModel(status="Success", message="Password has been successfully changed")
        elif not user_session and not schema.password and not schema.new_password:
            auth_method_email: AuthMethod = (
                AuthMethod.query(session=db.session)
                .filter(
                    AuthMethod.auth_method == Email.get_name(),
                    AuthMethod.param == "email",
                    AuthMethod.value == schema.email,
                )
                .one_or_none()
            )
            if not auth_method_email:
                raise HTTPException(
                    status_code=404, detail=ResponseModel(status="Error", message="Email not found").dict()
                )
            if not auth_method_email.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=ResponseModel(status="Error", message="Auth method restricted for this user").dict(),
                )
            if auth_method_email.user.auth_methods.confirmed.value.lower() == "false":
                raise AuthFailed(
                    error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
                )
            db.session.add(
                AuthMethod(
                    user_id=auth_method_email.user_id,
                    auth_method=Email.get_name(),
                    param="reset_token",
                    value=random_string(),
                )
            )
            db.session.commit()
            background_tasks.add_task(
                send_change_password_confirmation,
                auth_method_email.user.auth_methods.email.value,
                f"{settings.APPLICATION_HOST}/email/reset?token={auth_method_email.user.auth_methods.reset_token.value}",
            )
            return ResponseModel(status="Success", message="Reset link has been successfully mailed")
        elif not user_session and schema.password and schema.new_password:
            raise HTTPException(status_code=403, detail=ResponseModel(status="Error", message="Missing session").dict())
        raise HTTPException(
            status_code=422, detail=ResponseModel(status="Error", message="Unprocessable entity").dict()
        )

    @staticmethod
    async def _reset_password(schema: ResetPassword, reset_token: str = Header(min_length=1)) -> ResponseModel:
        auth_method = (
            AuthMethod.query(session=db.session)
            .filter(
                AuthMethod.auth_method == Email.get_name(),
                AuthMethod.param == "email",
                AuthMethod.value == schema.email,
            )
            .one_or_none()
        )
        if not auth_method:
            raise HTTPException(status_code=404, detail=ResponseModel(status="Error", message="Email not found"))
        if (
            not auth_method.user.auth_methods.reset_token
            or auth_method.user.auth_methods.reset_token.value != reset_token
        ):
            raise HTTPException(
                status_code=403,
                detail=ResponseModel(status="Error", message="Incorrect reset token").dict(),
            )
        salt = random_string()
        auth_method.user.auth_methods.hashed_password.value = Email._hash_password(schema.new_password, salt)
        auth_method.user.auth_methods.salt.value = salt
        auth_method.user.auth_methods.reset_token.is_deleted = True
        db.session.commit()
        return ResponseModel(status="Success", message="Password has been successfully changed")
