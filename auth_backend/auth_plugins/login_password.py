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
    email: str
    hashed_password: str
    salt: str
    confirmed: bool
    confirmation_token: str
    reset_token: str | None
    cols: Final[list[str]] = [EMAIL, HASHED_PASSWORD, SALT, CONFIRMED, CONFIRMATION_TOKEN, RESET_TOKEN]

    @staticmethod
    def hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    def __init__(self, *, email: str, password: str, salt: str | None = None):
        self.email = email
        self.salt = salt or get_salt()
        self.hashed_password = LoginPassword.hash_password(password, salt=self.salt)
        super().__init__()

    def register(self, db_session: Session, *, user_id: int | None = None) -> str | None:
        email_token = str(uuid4())
        if (query :=
        db_session.query(AuthMethod)
                .filter(
            AuthMethod.auth_method == LoginPassword.__name__,
            AuthMethod.param == EMAIL,
            AuthMethod.value == self.email,
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
        self.confirmed = False
        self.confirmation_token = str(uuid4())
        self.reset_token = None
        db_session.add(AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=EMAIL, value=self.email))
        db_session.add(AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=HASHED_PASSWORD,
                                  value=self.hashed_password))
        db_session.add(AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=SALT, value=self.salt))
        db_session.add(
            AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=CONFIRMED, value=str(self.confirmed)))
        db_session.add(AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=CONFIRMATION_TOKEN,
                                  value=self.confirmation_token))
        db_session.add(
            AuthMethod(user_id=user_id, auth_method=LoginPassword.__name__, param=RESET_TOKEN, value=self.reset_token))
        db_session.flush()
        return str(email_token)

    def login(self, db_session: Session, **kwargs) -> UserSession | None:
        if not (
                query := db_session.query(AuthMethod)
                        .filter(
                    AuthMethod.auth_method == self.__class__.__name__,
                    AuthMethod.param == EMAIL,
                    AuthMethod.value == self.email,
                )
                        .one_or_none()
        ):
            raise AuthFailed(error="Incorrect login or password")
        secrets = {row.param: row.value for row in query.user.get_auth_methods(self.__class__.__name__)}
        if not secrets.get(CONFIRMED):
            raise AuthFailed(
                error="Registration wasn't completed. Try to registrate again and do not forget to approve your email")
        if (
                secrets.get(EMAIL) != self.email
                or secrets.get(HASHED_PASSWORD) != self.hashed_password
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
