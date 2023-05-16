import hashlib
import logging

from fastapi import Depends, Header, HTTPException, Request
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import constr, validator
from sqlalchemy import func

from auth_backend.base import Base, StatusResponseModel
from auth_backend.exceptions import (
    AlreadyExists,
    AuthFailed,
    IncorrectUserAuthType,
    SessionExpired,
    TooManyEmailRequests,
)
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import get_settings
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.smtp import SendEmailMessage

from .auth_method import AuthMethodMeta, MethodMeta, Session, random_string


settings = get_settings()
logger = logging.getLogger(__name__)


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


class EmailParams(MethodMeta):
    __auth_method__ = "Email"
    __fields__ = frozenset(
        (
            "email",
            "hashed_password",
            "salt",
            "confirmed",
            "confirmation_token",
            "tmp_email",
            "reset_token",
            "tmp_email_confirmation_token",
        )
    )

    __required_fields__ = frozenset(("email", "hashed_password", "salt", "confirmed", "confirmation_token"))

    email: AuthMethod = None
    hashed_password: AuthMethod = None
    salt: AuthMethod = None
    confirmed: AuthMethod = None
    confirmation_token: AuthMethod = None
    tmp_email: AuthMethod = None
    reset_token: AuthMethod = None
    tmp_email_confirmation_token: AuthMethod = None


class Email(AuthMethodMeta):
    prefix = "/email"

    fields = EmailParams

    def __init__(self):
        super().__init__()

        self.router.add_api_route("/approve", self._approve_email, methods=["GET"], response_model=StatusResponseModel)
        self.router.add_api_route(
            "/reset/email/request", self._request_reset_email, methods=["POST"], response_model=StatusResponseModel
        )
        self.router.add_api_route(
            "/reset/email", self._reset_email, methods=["GET"], response_model=StatusResponseModel
        )
        self.router.add_api_route(
            "/reset/password/request",
            self._request_reset_password,
            methods=["POST"],
            response_model=StatusResponseModel,
        )
        self.router.add_api_route(
            "/reset/password", self._reset_password, methods=["POST"], response_model=StatusResponseModel
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
        if query.user.auth_methods.email.confirmed.value.lower() == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if query.user.auth_methods.email.email.value.lower() != user_inp.email.lower() or not Email._validate_password(
            user_inp.password,
            query.user.auth_methods.email.hashed_password.value,
            query.user.auth_methods.email.salt.value,
        ):
            raise AuthFailed(error="Incorrect login or password")
        return await cls._create_session(query.user, user_inp.scopes, db_session=db.session, session_name=session_name)

    @staticmethod
    async def _add_to_db(user_inp: EmailRegister, confirmation_token: str, user: User) -> None:
        salt = random_string()
        hashed_password = Email._hash_password(user_inp.password, salt)
        map = {
            "email": user_inp.email,
            "hashed_password": hashed_password,
            "salt": salt,
            "confirmed": str(False),
            "confirmation_token": confirmation_token,
        }
        await user.auth_methods.email.bulk_create(map)

    @staticmethod
    async def _change_confirmation_link(user: User, confirmation_token: str) -> None:
        if user.auth_methods.email.confirmed.value == "true":
            raise AlreadyExists(User, user.id)
        else:
            user.auth_methods.email.confirmation_token.value = confirmation_token

    @classmethod
    async def _register(
        cls,
        request: Request,
        user_inp: EmailRegister,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> StatusResponseModel:
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
            try:
                SendEmailMessage.send(
                    user_inp.email,
                    request.client.host,
                    "main_confirmation.html",
                    "Подтверждение регистрации Твой ФФ!",
                    db.session,
                    background_tasks,
                    url=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
                )
            except TooManyEmailRequests as ex:
                raise HTTPException(
                    status_code=429,
                    detail=StatusResponseModel(
                        status="Error",
                        message=f"Too many requests. Delay time: {int(ex.delay_time.total_seconds())} seconds.",
                    ).dict(),
                )
            finally:
                db.session.commit()
            return StatusResponseModel(status="Success", message="Email confirmation link sent")
        if user_session:
            user = await cls._get_user(user_session=user_session, db_session=db.session)
            if not user:
                raise SessionExpired(user_session.token)
        else:
            user = await cls._create_user(db_session=db.session)
        await Email._add_to_db(user_inp, confirmation_token, user)
        try:
            SendEmailMessage.send(
                user_inp.email,
                request.client.host,
                "main_confirmation.html",
                "Подтверждение регистрации Твой ФФ!",
                db.session,
                background_tasks,
                url=f"{settings.APPLICATION_HOST}/email/approve?token={confirmation_token}",
            )
        except TooManyEmailRequests as ex:
            raise HTTPException(
                status_code=429,
                detail=StatusResponseModel(
                    status="Error",
                    message=f"Too many requests. Delay time: {int(ex.delay_time.total_seconds())} seconds.",
                ).dict(),
            )
        finally:
            db.session.commit()
        return StatusResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    @staticmethod
    def _validate_password(password: str, hashed_password: str, salt: str) -> bool:
        """Проверяет, что хеш пароля совпадает с хешем из БД"""
        return Email._hash_password(password, salt) == hashed_password

    @staticmethod
    async def _approve_email(token: str) -> StatusResponseModel:
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
            raise HTTPException(
                status_code=403, detail=StatusResponseModel(status="Error", message="Incorrect link").dict()
            )
        auth_method.user.auth_methods.email.confirmed.value = "true"
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email approved")

    @staticmethod
    async def _request_reset_email(
        request: Request,
        scheme: EmailChange,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    ) -> StatusResponseModel:
        if user_session.expired:
            raise SessionExpired(user_session.token)
        if not user_session.user.auth_methods.email:
            raise IncorrectUserAuthType()
        if user_session.user.auth_methods.email.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if user_session.user.auth_methods.email.email.value == scheme.email:
            raise HTTPException(
                status_code=401, detail=StatusResponseModel(status="Error", message="Email incorrect").dict()
            )
        token = random_string()
        await user_session.user.auth_methods.email.bulk_create(
            {"tmp_email_confirmation_token": token, "tmp_email": scheme.email}
        )
        try:
            SendEmailMessage.send(
                to_email=scheme.email,
                ip=request.client.host,
                message_file_name="mail_change_confirmation.html",
                subject="Смена почты Твой ФФ!",
                dbsession=db.session,
                background_tasks=background_tasks,
                url=f"{settings.APPLICATION_HOST}/email/reset/email/{user_session.user_id}?token={token}&email={scheme.email}",
            )
        except TooManyEmailRequests as ex:
            raise HTTPException(
                status_code=429,
                detail=StatusResponseModel(
                    status="Error",
                    message=f"Too many requests. Delay time: {int(ex.delay_time.total_seconds())} seconds.",
                ).dict(),
            )
        finally:
            db.session.commit()
        return StatusResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    async def _reset_email(token: str) -> StatusResponseModel:
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
                status_code=403,
                detail=StatusResponseModel(status="Error", message="Incorrect confirmation token").dict(),
            )
        user: User = auth.user
        if user.auth_methods.email.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        user.auth_methods.email.email.value = user.auth_methods.email.tmp_email.value
        user.auth_methods.email.tmp_email_confirmation_token.is_deleted = True
        user.auth_methods.email.tmp_email.is_deleted = True
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email successfully changed")

    @staticmethod
    async def _request_reset_password(
        request: Request,
        schema: RequestResetPassword,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> StatusResponseModel:
        salt = random_string()
        if user_session and schema.new_password and schema.password:
            if user_session.expired:
                raise SessionExpired(user_session.token)
            if not user_session.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=StatusResponseModel(status="Error", message="Auth method restricted for this user").dict(),
                )
            if not Email._validate_password(
                schema.password,
                user_session.user.auth_methods.email.hashed_password.value,
                user_session.user.auth_methods.email.salt.value,
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
                    status_code=403, detail=StatusResponseModel(status="Error", message="Incorrect user session").dict()
                )
            user_session.user.auth_methods.email.hashed_password.value = Email._hash_password(schema.new_password, salt)
            user_session.user.auth_methods.email.salt.value = salt
            try:
                SendEmailMessage.send(
                    to_email=user_session.user.auth_methods.email.email.value,
                    ip=request.client.host,
                    message_file_name="password_change_notification.html",
                    subject="Смена пароля Твой ФФ!",
                    dbsession=db.session,
                    background_tasks=background_tasks,
                )
            except TooManyEmailRequests as ex:
                raise HTTPException(
                    status_code=429,
                    detail=StatusResponseModel(
                        status="Error",
                        message=f"Too many requests. Delay time: {int(ex.delay_time.total_seconds())} seconds.",
                    ).dict(),
                )
            finally:
                db.session.commit()
            return StatusResponseModel(status="Success", message="Password has been successfully changed")
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
                    status_code=404, detail=StatusResponseModel(status="Error", message="Email not found").dict()
                )
            if not auth_method_email.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=StatusResponseModel(status="Error", message="Auth method restricted for this user").dict(),
                )
            if auth_method_email.user.auth_methods.email.confirmed.value.lower() == "false":
                raise AuthFailed(
                    error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
                )
            await auth_method_email.user.auth_methods.email.create("reset_token", random_string())
            try:
                SendEmailMessage.send(
                    to_email=auth_method_email.user.auth_methods.email.email.value,
                    ip=request.client.host,
                    message_file_name="password_change_confirmation.html",
                    subject="Смена пароля Твой ФФ!",
                    dbsession=db.session,
                    background_tasks=background_tasks,
                    url=f"{settings.APPLICATION_HOST}/email/reset?token={auth_method_email.user.auth_methods.email.reset_token.value}",
                )
            except TooManyEmailRequests as ex:
                raise HTTPException(
                    status_code=429,
                    detail=StatusResponseModel(
                        status="Error",
                        message=f"Too many requests. Delay time: {int(ex.delay_time.total_seconds())} seconds.",
                    ).dict(),
                )
            return StatusResponseModel(status="Success", message="Reset link has been successfully mailed")
        elif not user_session and schema.password and schema.new_password:
            raise HTTPException(
                status_code=403, detail=StatusResponseModel(status="Error", message="Missing session").dict()
            )
        raise HTTPException(
            status_code=422, detail=StatusResponseModel(status="Error", message="Unprocessable entity").dict()
        )

    @staticmethod
    async def _reset_password(schema: ResetPassword, reset_token: str = Header(min_length=1)) -> StatusResponseModel:
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
            raise HTTPException(status_code=404, detail=StatusResponseModel(status="Error", message="Email not found"))
        if (
            not auth_method.user.auth_methods.email.reset_token
            or auth_method.user.auth_methods.email.reset_token.value != reset_token
        ):
            raise HTTPException(
                status_code=403,
                detail=StatusResponseModel(status="Error", message="Incorrect reset token").dict(),
            )
        salt = random_string()
        auth_method.user.auth_methods.email.hashed_password.value = Email._hash_password(schema.new_password, salt)
        auth_method.user.auth_methods.email.salt.value = salt
        auth_method.user.auth_methods.email.reset_token.is_deleted = True
        db.session.commit()
        return StatusResponseModel(status="Success", message="Password has been successfully changed")
