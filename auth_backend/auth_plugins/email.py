import hashlib
import logging
from typing import Annotated, Self

from annotated_types import MinLen
from event_schema.auth import UserLogin
from fastapi import Depends, Header, HTTPException, Request
from fastapi.background import BackgroundTasks
from fastapi_sqlalchemy import db
from pydantic import field_validator, model_validator
from sqlalchemy import func

from auth_backend.auth_method import AuthMethodMeta
from auth_backend.auth_method import Session
from auth_backend.auth_method.method_mixins import LoginableMixin, RegistrableMixin
from auth_backend.base import Base, StatusResponseModel
from auth_backend.exceptions import AlreadyExists, AuthFailed, IncorrectUserAuthType, SessionExpired
from auth_backend.kafka.kafka import get_kafka_producer
from auth_backend.models.db import AuthMethod, User, UserSession
from auth_backend.schemas.types.scopes import Scope
from auth_backend.settings import get_settings
from auth_backend.utils.auth_params import get_auth_params
from auth_backend.utils.security import UnionAuth
from auth_backend.utils.smtp import SendEmailMessage
from auth_backend.utils.string import random_string


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
    email: Annotated[str, MinLen(1)]
    password: Annotated[str, MinLen(1)]
    scopes: list[Scope] | None = None
    session_name: str | None = None
    email_validator = field_validator("email")(check_email)


class EmailRegister(Base):
    email: Annotated[str, MinLen(1)]
    password: Annotated[str, MinLen(1)]
    email_validator = field_validator("email")(check_email)


class EmailChange(Base):
    email: Annotated[str, MinLen(1)]

    email_validator = field_validator("email")(check_email)


class ResetPassword(Base):
    password: Annotated[str, MinLen(1)]
    new_password: Annotated[str, MinLen(1)]

    @model_validator(mode="after")
    def check_passwords_dont_match(self) -> Self:
        if not (self.password or self.new_password):
            return self
        assert self.new_password != self.password, "Passwords must be different"
        return self


class RequestResetForgottenPassword(Base):
    email: Annotated[str, MinLen(1)]

    email_validator = field_validator("email")(check_email)


class ResetForgottenPassword(Base):
    new_password: Annotated[str, MinLen(1)]


class Email(LoginableMixin, RegistrableMixin, AuthMethodMeta):
    prefix = "/email"

    @staticmethod
    def _get_email_params(user_id: int) -> dict[str, AuthMethod]:
        return get_auth_params(user_id, Email.get_name(), db.session)

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
            "/reset/password/restore",
            self._request_reset_forgotten_password,
            methods=["POST"],
            response_model=StatusResponseModel,
        )
        self.router.add_api_route(
            "/reset/password", self._reset_forgotten_password, methods=["POST"], response_model=StatusResponseModel
        )
        self.tags = ["Email"]

    @classmethod
    async def _login(cls, user_inp: EmailLogin, background_tasks: BackgroundTasks) -> Session:
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
            raise AuthFailed("Incorrect login or password", "Некорректный логин или пароль")
        auth_params = cls._get_email_params(query.user_id)
        if auth_params["confirmed"].value.lower() == "false":
            raise AuthFailed(
                "Registration wasn't completed. Try to registrate again and do not forget to approve your email",
                "Регистрация не была завершена. Попробуйте зарегистрироваться снова и не забудьте подтвердить почту",
            )
        if auth_params["email"].value.lower() != user_inp.email.lower() or not Email._validate_password(
            user_inp.password,
            auth_params["hashed_password"].value,
            auth_params["salt"].value,
        ):
            raise AuthFailed("Incorrect login or password", "Некорректный логин или пароль")
        userdata = await Email._convert_data_to_userdata_format({"email": auth_params["email"].value})
        await get_kafka_producer().produce(
            settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            Email.generate_kafka_key(query.user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        return await cls._create_session(
            query.user, user_inp.scopes, db_session=db.session, session_name=user_inp.session_name
        )

    @staticmethod
    async def _add_to_db(user_inp: EmailRegister, confirmation_token: str, user: User) -> dict:
        salt = random_string()
        hashed_password = Email._hash_password(user_inp.password, salt)
        method_params = {
            "email": user_inp.email,
            "hashed_password": hashed_password,
            "salt": salt,
            "confirmed": str(False),
            "confirmation_token": confirmation_token,
        }
        for k, v in method_params.items():
            AuthMethod.create(user_id=user.id, auth_method="email", param=k, value=v, session=db.session)
        return method_params

    @staticmethod
    async def _change_confirmation_link(user: User, confirmation_token: str) -> None:
        auth_params = Email._get_email_params(user.id)
        if auth_params["confirmed"].value == "true":
            raise AlreadyExists(User, user.id)
        else:
            auth_params["confirmation_token"].value = confirmation_token

    @classmethod
    async def _register(
        cls,
        request: Request,
        user_inp: EmailRegister,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=True, auto_error=True)),
    ) -> StatusResponseModel:
        confirmation_token: str = random_string()
        auth_method: AuthMethod | None = (
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
            return StatusResponseModel(
                status="Success", message="Email confirmation link sent", ru="Ссылка отправлена на почту"
            )
        if user_session:
            user = await cls._get_user(user_session=user_session, db_session=db.session)
            if not user:
                raise SessionExpired(user_session.token)
        else:
            user = await cls._create_user(db_session=db.session)
        method_params = await Email._add_to_db(user_inp, confirmation_token, user)
        method_params["password"] = user_inp.password  # В user_updated передаем пароль в открытую
        SendEmailMessage.send(
            user_inp.email,
            request.client.host,
            "main_confirmation.html",
            "Подтверждение регистрации Твой ФФ!",
            db.session,
            background_tasks,
            url=f"{settings.APPLICATION_HOST}/auth/register/success?token={confirmation_token}",
        )

        old_user = None
        if user_session:
            old_user = {"user_id": user_session.user.id}
        await AuthMethodMeta.user_updated({"user_id": user.id, Email.get_name(): method_params}, old_user)

        db.session.commit()
        return StatusResponseModel(
            status="Success", message="Email confirmation link sent", ru="Ссылка отправлена на почту"
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
    async def _approve_email(token: str, background_tasks: BackgroundTasks) -> StatusResponseModel:
        auth_method: AuthMethod | None = (
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
                status_code=403,
                detail=StatusResponseModel(
                    status="Error", message="Incorrect link", ru="Некорректная ссылка"
                ).model_dump(),
            )
        auth_params = Email._get_email_params(auth_method.user.id)
        auth_params["confirmed"].value = "true"
        userdata = await Email._convert_data_to_userdata_format({"email": auth_params["email"].value})
        await get_kafka_producer().produce(
            settings.KAFKA_USER_LOGIN_TOPIC_NAME,
            Email.generate_kafka_key(auth_method.user.id),
            userdata,
            bg_tasks=background_tasks,
        )
        await AuthMethodMeta.user_updated(
            {"user_id": auth_method.user.id, Email.get_name(): {"confirmed": True}},
            {"user_id": auth_method.user.id, Email.get_name(): {"confirmed": False}},
        )
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email approved", ru="Почта подтверждена")

    @classmethod
    async def _request_reset_email(
        cls,
        request: Request,
        scheme: EmailChange,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    ) -> StatusResponseModel:
        auth_params = Email._get_email_params(user_session.user_id)
        if "email" not in auth_params:
            raise IncorrectUserAuthType()
        if auth_params["confirmed"].value == "false":
            raise AuthFailed(
                "Registration wasn't completed. Try to registrate again and do not forget to approve your email",
                "Регистрация не была завершена. Паоробуйте зарегистрироваться снова и не забудьте подтвердить почту",
            )
        if auth_params["email"].value == scheme.email:
            raise HTTPException(
                status_code=401,
                detail=StatusResponseModel(
                    status="Error", message="Email incorrect", ru="Некорректная почта"
                ).model_dump(),
            )

        old_user = {"user_id": user_session.user_id, cls.get_name(): {}}
        new_user = {"user_id": user_session.user_id, cls.get_name(): {}}
        token = random_string(length=settings.TOKEN_LENGTH)
        if "tmp_email" in auth_params:
            old_user[cls.get_name()]["tmp_email"] = auth_params["tmp_email"].value
            auth_params["tmp_email"].is_deleted = True
            old_user[cls.get_name()]["tmp_email_confirmation_token"] = auth_params["tmp_email_confirmation_token"].value
            auth_params["tmp_email_confirmation_token"].is_deleted = True
            db.session.flush()
        AuthMethod.create(
            user_id=user_session.user_id,
            auth_method="email",
            param="tmp_email_confirmation_token",
            value=token,
            session=db.session,
        )
        new_user[cls.get_name()]["tmp_email_confirmation_token"] = token
        AuthMethod.create(
            user_id=user_session.user_id, auth_method="email", param="tmp_email", value=scheme.email, session=db.session
        )
        new_user[cls.get_name()]["tmp_email"] = scheme.email
        SendEmailMessage.send(
            to_email=scheme.email,
            ip=request.client.host,
            message_file_name="mail_change_confirmation.html",
            subject="Смена почты Твой ФФ!",
            dbsession=db.session,
            background_tasks=background_tasks,
            url=f"{settings.APPLICATION_HOST}/auth/reset/email?token={token}",
        )
        await AuthMethodMeta.user_updated(old_user, new_user)
        db.session.commit()
        return StatusResponseModel(
            status="Success", message="Email confirmation link sent", ru="Ссылка отправлена на почту"
        )

    @staticmethod
    async def _reset_email(token: str, background_tasks: BackgroundTasks) -> StatusResponseModel:
        auth: AuthMethod | None = (
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
                detail=StatusResponseModel(
                    status="Error", message="Incorrect confirmation token", ru="Неправильный токен подтверждения"
                ).model_dump(),
            )
        auth_params = Email._get_email_params(auth.user_id)
        user: User = auth.user
        if auth_params["confirmed"].value == "false":
            raise AuthFailed(
                "Registration wasn't completed. Try to registrate again and do not forget to approve your email",
                "Регистрация не была завершена. Паоробуйте зарегистрироваться снова и не забудьте подтвердить почту",
            )
        old_user = {
            "user_id": user.id,
            Email.get_name(): {
                "email": auth_params["email"].value,
                "tmp_email": auth_params["tmp_email"].value,
                "tmp_email_confirmation_token": auth_params["tmp_email_confirmation_token"].value,
            },
        }
        auth_params["email"].value = auth_params["tmp_email"].value
        auth_params["tmp_email_confirmation_token"].is_deleted = True
        auth_params["tmp_email"].is_deleted = True
        new_user = {
            "user_id": user.id,
            Email.get_name(): {"email": auth_params["email"].value},
        }
        userdata = await Email._convert_data_to_userdata_format({"email": auth_params["email"].value})
        await get_kafka_producer().produce(
            settings.KAFKA_USER_LOGIN_TOPIC_NAME, Email.generate_kafka_key(user.id), userdata, bg_tasks=background_tasks
        )
        await AuthMethodMeta.user_updated(old_user, new_user)
        db.session.commit()
        return StatusResponseModel(status="Success", message="Email successfully changed", ru="Почта изменена")

    @staticmethod
    async def _request_reset_password(
        request: Request,
        schema: ResetPassword,
        background_tasks: BackgroundTasks,
        user_session: UserSession = Depends(UnionAuth(scopes=[], allow_none=False, auto_error=True)),
    ) -> StatusResponseModel:
        old_user = {"user_id": user_session.user_id, Email.get_name(): {}}
        new_user = {"user_id": user_session.user_id, Email.get_name(): {}}
        auth_params = Email._get_email_params(user_session.user.id)
        if "email" not in auth_params:
            raise HTTPException(
                status_code=401,
                detail=StatusResponseModel(
                    status="Error",
                    message="Auth method restricted for this user",
                    ru="Метод аутентификации не установлен для пользователя",
                ).model_dump(),
            )
        salt = random_string()
        if not Email._validate_password(
            schema.password,
            auth_params["hashed_password"].value,
            auth_params["salt"].value,
        ):
            raise AuthFailed("Incorrect password", "Неправильный пароль")
        old_user[Email.get_name()]["hashed_password"] = auth_params["hashed_password"].value
        old_user[Email.get_name()]["salt"] = auth_params["salt"].value
        auth_params["hashed_password"].value = Email._hash_password(schema.new_password, salt)
        auth_params["salt"].value = salt
        new_user[Email.get_name()]["hashed_password"] = auth_params["hashed_password"].value
        new_user[Email.get_name()]["salt"] = auth_params["salt"].value
        SendEmailMessage.send(
            to_email=auth_params["email"].value,
            ip=request.client.host,
            message_file_name="password_change_notification.html",
            subject="Смена пароля Твой ФФ!",
            dbsession=db.session,
            background_tasks=background_tasks,
        )
        await AuthMethodMeta.user_updated(old_user, new_user)
        db.session.commit()
        return StatusResponseModel(
            status="Success", message="Password has been successfully changed", ru="Пароль изменен"
        )

    @staticmethod
    async def _request_reset_forgotten_password(
        request: Request, schema: RequestResetForgottenPassword, background_tasks: BackgroundTasks
    ) -> StatusResponseModel:
        auth_method_email: AuthMethod | None = (
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
                status_code=404,
                detail=StatusResponseModel(
                    status="Error", message="Email not found", ru="Почта не найдена"
                ).model_dump(),
            )
        auth_params = Email._get_email_params(auth_method_email.user.id)
        old_user = {"user_id": auth_method_email.user.id, Email.get_name(): {}}
        new_user = {"user_id": auth_method_email.user.id, Email.get_name(): {}}
        if "email" not in auth_params:
            raise HTTPException(
                status_code=401,
                detail=StatusResponseModel(
                    status="Error",
                    message="Auth method restricted for this user",
                    ru="Метод аутентификации не установлен для пользователя",
                ).model_dump(),
            )
        if auth_params["confirmed"].value.lower() == "false":
            raise AuthFailed(
                "Registration wasn't completed. Try to registrate again and do not forget to approve your email",
                "Регистрация не была завершена. Паоробуйте зарегистрироваться снова и не забудьте подтвердить почту",
            )
        if "reset_token" in auth_params:
            old_user[Email.get_name()]["reset_token"] = auth_params["reset_token"].value
            auth_params["reset_token"].is_deleted = True
            db.session.flush()
        reset_token_value = random_string(length=settings.TOKEN_LENGTH)
        AuthMethod.create(
            user_id=auth_method_email.user.id,
            auth_method="email",
            param="reset_token",
            value=reset_token_value,
            session=db.session,
        )
        new_user[Email.get_name()]["reset_token"] = reset_token_value
        auth_params = Email._get_email_params(auth_method_email.user.id)
        SendEmailMessage.send(
            to_email=auth_params["email"].value,
            ip=request.client.host,
            message_file_name="password_change_confirmation.html",
            subject="Смена пароля Твой ФФ!",
            dbsession=db.session,
            background_tasks=background_tasks,
            url=f"{settings.APPLICATION_HOST}/auth/reset/password?token={auth_params['reset_token'].value}",
        )
        await AuthMethodMeta.user_updated(old_user, new_user)
        db.session.commit()
        return StatusResponseModel(
            status="Success", message="Reset link has been successfully mailed", ru="Ссылка отправлена на почту"
        )

    @staticmethod
    async def _reset_forgotten_password(
        schema: ResetForgottenPassword, reset_token: str = Header(min_length=1)
    ) -> StatusResponseModel:
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
                status_code=403,
                detail=StatusResponseModel(
                    status="Error", message="Invalid reset token", ru="Неправильный токен сброса"
                ).model_dump(),
            )
        auth_params = Email._get_email_params(auth_method.user.id)
        old_user = {"user_id": auth_method.user.id, Email.get_name(): {"reset_token": auth_params["reset_token"].value}}
        new_user = {"user_id": auth_method.user.id, Email.get_name(): {}}
        salt = random_string()
        auth_params["hashed_password"].value = Email._hash_password(schema.new_password, salt)
        new_user[Email.get_name()]["password"] = schema.new_password  # В user_updated передаем пароль в открытую
        new_user[Email.get_name()]["hashed_password"] = auth_params["hashed_password"].value
        auth_params["salt"].value = salt
        new_user[Email.get_name()]["salt"] = auth_params["salt"].value
        auth_params["reset_token"].is_deleted = True
        await AuthMethodMeta.user_updated(old_user, new_user)
        db.session.commit()
        return StatusResponseModel(
            status="Success", message="Password has been successfully changed", ru="Пароль изменен"
        )

    @classmethod
    async def _convert_data_to_userdata_format(cls, data: dict[str, str]) -> UserLogin:
        items = [{"category": "Контакты", "param": "Электронная почта", "value": data["email"]}]
        result = {"items": items, "source": cls.get_name()}
        return UserLogin.model_validate(result)
