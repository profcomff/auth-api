import hashlib
import random
import string
from typing import Final
from uuid import uuid4

from sqlalchemy.orm import Session

from auth_backend.exceptions import ObjectNotFound, AlreadyExists, AuthFailed
from auth_backend.models import UserSession, User, AuthMethod
from .auth_interface import AuthInterface

# Constant strings to use instead of typing
EMAIL: Final[str] = "email"
HASHED_PASSWORD: Final[str] = "hashed_password"
SALT: Final[str] = "salt"
CONFIRMED: Final[str] = "confirmed"
CONFIRMATION_TOKEN: Final[str] = "confirmation_token"
RESET_TOKEN: Final[str] = "reset_token"


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class LoginPassword(AuthInterface):
    email: AuthInterface.Prop
    hashed_password: AuthInterface.Prop
    salt: AuthInterface.Prop
    confirmed: AuthInterface.Prop
    confirmation_token: AuthInterface.Prop
    reset_token: AuthInterface.Prop
    cols = []

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    def __init__(self, *, email: str, password: str, salt: str | None = None):
        self.email = AuthInterface.Prop(value=email, datatype=str, param=EMAIL)
        self.salt = AuthInterface.Prop(value=salt or get_salt(), datatype=str, param=SALT)
        self.hashed_password = AuthInterface.Prop(
            value=LoginPassword.hash_password(password, salt=self.salt.value), datatype=str, param=HASHED_PASSWORD
        )
        super().__init__()

    def register(self, db_session: Session, *, user_id: int | None = None) -> str | None:
        email_token = str(uuid4())
        if (query :=
        db_session.query(AuthMethod)
                .filter(
            AuthMethod.auth_method == LoginPassword.__name__,
            AuthMethod.param == self.email.param,
            AuthMethod.value == self.email.value,
        )
                .one_or_none()
        ):
            if query.confirmed:
                raise AlreadyExists(User, query.user_id)
            else:
                for row in query.user.get_auth_methods(LoginPassword.__name__):
                    row.value = email_token if row.param == CONFIRMATION_TOKEN else row.value
                db_session.flush()
                return str(email_token)
        if not user_id:
            db_session.add(user := User())
            db_session.flush()
        else:
            user = db_session.query(User).get(user_id)
        if not user:
            raise ObjectNotFound(User, user_id)
        self.confirmed = AuthInterface.Prop(datatype=bool, param=CONFIRMED, value=False)
        self.confirmation_token = AuthInterface.Prop(datatype=str, param=CONFIRMATION_TOKEN, value=str(uuid4()))
        self.reset_token = AuthInterface.Prop(datatype=str, param=RESET_TOKEN, value=None)
        for row in (
                self.email, self.hashed_password, self.salt, self.confirmed, self.confirmation_token, self.reset_token):
            db_session.add(
                AuthMethod(user_id=user.id, auth_method=LoginPassword.__name__, value=row.value, param=row.param)
            )
        db_session.flush()
        return str(email_token)

    def login(self, db_session: Session, **kwargs) -> UserSession | None:
        if not (
                query := db_session.query(AuthMethod)
                        .filter(
                    AuthMethod.auth_method == self.__class__.__name__,
                    AuthMethod.param == EMAIL,
                    AuthMethod.value == self.email.value,
                )
                        .one_or_none()
        ):
            raise AuthFailed(error="Incorrect login or password")
        secrets = {row.param: row.value for row in query.user.get_auth_methods(self.__class__.__name__)}
        if not secrets.get(CONFIRMED):
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email")
        if (
                secrets.get(self.email.param) != self.email.value
                or secrets.get(self.hashed_password.param) != self.hashed_password.value
        ):
            raise AuthFailed(error="Incorrect login or password")
        db_session.add(session := UserSession(user_id=query.user.id, token=str(uuid4())))
        db_session.flush()
        return session

    @staticmethod
    def change_params(token: str, db_session: Session,
                      new_email: str | None = None, new_password: str | None = None) -> None:
        session: UserSession = db_session.query(UserSession).filter(UserSession.token == token).one_or_none()
        if session.expired:
            raise AuthFailed(error="Session expired, log in system again")
        for row in session.user.get_auth_methods(LoginPassword.__name__):
            if row.param == EMAIL:
                row.value = new_email or row.value
            if row.param == HASHED_PASSWORD:
                salt = get_salt()
                row.value = LoginPassword.hash_password(new_password, salt)
        db_session.flush()
        return None

    @staticmethod
    def forgot_password():
        pass
