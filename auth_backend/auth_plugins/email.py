import hashlib
import logging
from typing import Self

from event_schema.auth import UserLogin
from fastapi import Depends, Header, HTTPException, Request
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import constr, field_validator, model_validator
from sqlalchemy import func

from auth_backend.base import Base, StatusResponseModel
from auth_backend.exceptions import AlreadyExists, AuthFailed, IncorrectUserAuthType, SessionExpired
from auth_backend.kafka.kafka import get_kafka_producer
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
    scopes: list[Scope] | None = None
    session_name: str | None = None
    email_validator = field_validator("email")(check_email)


class EmailRegister(Base):
    email: constr(min_length=1)
    password: constr(min_length=1)
    email_validator = field_validator("email")(check_email)


class EmailChange(Base):
    email: constr(min_length=1)

    email_validator = field_validator("email")(check_email)


class RequestResetPassword(Base):
    email: constr(min_length=1) | None = None
    password: constr(min_length=1) | None = None
    new_password: constr(min_length=1) | None = None

    @model_validator(mode="after")
    def check_passwords_dont_match(self) -> Self:
        if not (self.password or self.new_password):
            return self
        assert self.new_password != self.password, "Пароли должны различаться"
        return self

    @model_validator(mode="after")
    def check_email_or_session(self) -> Self:
        passowrds = bool(self.password) and bool(self.new_password)
        assert bool(self.email) ^ bool(passowrds), "Должна быть задана либо почта, либо два пароля"
        return self

    email_validator = field_validator("email")(check_email)


class ResetPassword(Base):
    new_password: constr(min_length=1)


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
        return await cls._create_session(
            query.user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

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
            SendEmailMessage.send(
                user_inp.email,
                request.client.host,
                "main_confirmation.html",
                "Подтверждение регистрации Твой ФФ!",
                db.session,
                background_tasks,
                url=f"{settings.APPLICATION_HOST}/auth/register/success?token={confirmation_token}",
            )
            db.session.commit()
            return StatusResponseModel(status="Success", message="Email confirmation link sent")
        if user_session:
            user = await cls._get_user(user_session=user_session, db_session=db.session)
            if not user:
                raise SessionExpired(user_session.token)
        else:
            user = await cls._create_user(db_session=db.session)
        await Email._add_to_db(user_inp, confirmation_token, user)
        SendEmailMessage.send(
            user_inp.email,
            request.client.host,
            "main_confirmation.html",
            "Подтверждение регистрации Твой ФФ!",
            db.session,
            background_tasks,
            url=f"{settings.APPLICATION_HOST}/auth/register/success?token={confirmation_token}",
        )
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
    async def _approve_email(token: str, background_tasks: BackgroundTasks) -> StatusResponseModel:
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
                status_code=403, detail=StatusResponseModel(status="Error", message="Incorrect link").model_dump()
            )
        auth_method.user.auth_methods.email.confirmed.value = "true"
        userdata = Email._convert_data_to_userdata_format({"email": auth_method.user.auth_methods.email.email.value})
        await get_kafka_producer().produce(
            settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            Email.generate_kafka_key(auth_method.user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email approved")

    @staticmethod
    async def _request_reset_email(
        request: Request,
        scheme: EmailChange,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    ) -> StatusResponseModel:
        if not user_session.user.auth_methods.email:
            raise IncorrectUserAuthType()
        if user_session.user.auth_methods.email.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        if user_session.user.auth_methods.email.email.value == scheme.email:
            raise HTTPException(
                status_code=401, detail=StatusResponseModel(status="Error", message="Email incorrect").model_dump()
            )
        token = random_string(length=32)
        if user_session.user.auth_methods.email.tmp_email is not None:
            user_session.user.auth_methods.email.tmp_email.is_deleted = True
            user_session.user.auth_methods.email.tmp_email_confirmation_token.is_deleted = True
            db.session.flush()
        await user_session.user.auth_methods.email.bulk_create(
            {"tmp_email_confirmation_token": token, "tmp_email": scheme.email}
        )
        SendEmailMessage.send(
            to_email=scheme.email,
            ip=request.client.host,
            message_file_name="mail_change_confirmation.html",
            subject="Смена почты Твой ФФ!",
            dbsession=db.session,
            background_tasks=background_tasks,
            url=f"{settings.APPLICATION_HOST}/auth/reset/email?token={token}",
        )
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email confirmation link sent")

    @staticmethod
    async def _reset_email(token: str, background_tasks: BackgroundTasks) -> StatusResponseModel:
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
                detail=StatusResponseModel(status="Error", message="Incorrect confirmation token").model_dump(),
            )
        user: User = auth.user
        if user.auth_methods.email.confirmed.value == "false":
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
            )
        user.auth_methods.email.email.value = user.auth_methods.email.tmp_email.value
        user.auth_methods.email.tmp_email_confirmation_token.is_deleted = True
        user.auth_methods.email.tmp_email.is_deleted = True
        userdata = Email._convert_data_to_userdata_format({"email": user.auth_methods.email.email.value})
        await get_kafka_producer().produce(
            settings.KAFKA_USER_LOGIN_TOPIC_NAME, Email.generate_kafka_key(user.id), userdata, bg_tasks=background_tasks
        )
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email successfully changed")

    @staticmethod
    async def _request_reset_password(
        request: Request,
        schema: RequestResetPassword,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> StatusResponseModel:
        """
        Передать надо либо email, либо сессию + новый пароль + старый пароль
        """
        salt = random_string()
        if user_session and schema.new_password and schema.password:
            if user_session.expired:
                raise SessionExpired(user_session.token)
            if not user_session.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=StatusResponseModel(
                        status="Error", message="Auth method restricted for this user"
                    ).model_dump(),
                )
            if not Email._validate_password(
                schema.password,
                user_session.user.auth_methods.email.hashed_password.value,
                user_session.user.auth_methods.email.salt.value,
            ):
                raise AuthFailed(error="Incorrect password")
            user_session.user.auth_methods.email.hashed_password.value = Email._hash_password(schema.new_password, salt)
            user_session.user.auth_methods.email.salt.value = salt
            SendEmailMessage.send(
                to_email=user_session.user.auth_methods.email.email.value,
                ip=request.client.host,
                message_file_name="password_change_notification.html",
                subject="Смена пароля Твой ФФ!",
                dbsession=db.session,
                background_tasks=background_tasks,
            )
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
                    status_code=404, detail=StatusResponseModel(status="Error", message="Email not found").model_dump()
                )
            if not auth_method_email.user.auth_methods.email:
                raise HTTPException(
                    status_code=401,
                    detail=StatusResponseModel(
                        status="Error", message="Auth method restricted for this user"
                    ).model_dump(),
                )
            if auth_method_email.user.auth_methods.email.confirmed.value.lower() == "false":
                raise AuthFailed(
                    error="Registration wasn't completed. Try to registrate again and do not forget to approve your email"
                )
            if auth_method_email.user.auth_methods.email.reset_token is not None:
                auth_method_email.user.auth_methods.email.reset_token.is_deleted = True
                db.session.flush()
            await auth_method_email.user.auth_methods.email.create("reset_token", random_string(length=32))
            SendEmailMessage.send(
                to_email=auth_method_email.user.auth_methods.email.email.value,
                ip=request.client.host,
                message_file_name="password_change_confirmation.html",
                subject="Смена пароля Твой ФФ!",
                dbsession=db.session,
                background_tasks=background_tasks,
                url=f"{settings.APPLICATION_HOST}/auth/reset/password?token={auth_method_email.user.auth_methods.email.reset_token.value}",
            )
            return StatusResponseModel(status="Success", message="Reset link has been successfully mailed")
        elif not user_session and schema.password and schema.new_password:
            raise HTTPException(
                status_code=403, detail=StatusResponseModel(status="Error", message="Missing session").model_dump()
            )
        raise HTTPException(
            status_code=422, detail=StatusResponseModel(status="Error", message="Unprocessable entity").model_dump()
        )

    @staticmethod
    async def _reset_password(schema: ResetPassword, reset_token: str = Header(min_length=1)) -> StatusResponseModel:
        auth_method = (
            AuthMethod.query(session=db.session)
            .filter(
                AuthMethod.auth_method == Email.get_name(),
                AuthMethod.param == "reset_token",
                AuthMethod.value == reset_token,
            )
            .one_or_none()
        )
        if not auth_method:
            raise HTTPException(
                status_code=404, detail=StatusResponseModel(status="Error", message="Invalid reset token").model_dump()
            )
        salt = random_string()
        auth_method.user.auth_methods.email.hashed_password.value = Email._hash_password(schema.new_password, salt)
        auth_method.user.auth_methods.email.salt.value = salt
        auth_method.user.auth_methods.email.reset_token.is_deleted = True
        db.session.commit()
        return StatusResponseModel(status="Success", message="Password has been successfully changed")

    @classmethod
    def _convert_data_to_userdata_format(cls, data: dict[str, str]) -> UserLogin:
        items = [{"category": "contacts", "param": "email", "value": data["email"]}]
        result = {"items": items, "source": cls.get_name()}
        return UserLogin.model_validate(result)
