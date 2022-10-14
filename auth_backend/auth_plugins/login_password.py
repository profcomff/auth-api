import hashlib
import random
import string
from uuid import uuid4

from sqlalchemy.orm import Session as DBSession

from auth_backend.exceptions import ObjectNotFound, AlreadyExists, AuthFailed
from auth_backend.models import Session, User, AuthMethod
from .auth_interface import AuthInterface


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
    def __hash_password(password: str, salt: str):
        enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return enc.hex()

    def __init__(self, *, email: str, password: str, salt: str | None = None):
        self.email = AuthInterface.Prop(value=email, datatype=str, param="email")
        self.salt = AuthInterface.Prop(value=salt or get_salt(), datatype=str, param="salt")
        self.hashed_password = AuthInterface.Prop(
            value=LoginPassword.__hash_password(password, salt=self.salt.value), datatype=str, param="hashed_password"
        )
        super().__init__()

    def register(self, db_session: DBSession, *, user_id: int | None = None) -> str | None:
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
                    row.value = email_token if row.param == "confirmation_token" else row.value
                db_session.flush()
                return str(email_token)
        if not user_id:
            db_session.add(user := User())
            db_session.flush()
        else:
            user = db_session.query(User).get(user_id)
        if not user:
            raise ObjectNotFound(User, user_id)
        self.confirmed = AuthInterface.Prop(datatype=bool, param="confirmed", value=False)
        self.confirmation_token = AuthInterface.Prop(datatype=str, param="confirmation_token", value=str(uuid4()))
        self.reset_token = AuthInterface.Prop(datatype=str, param="reset_token", value=None)
        for row in (
        self.email, self.hashed_password, self.salt, self.confirmed, self.confirmation_token, self.reset_token):
            db_session.add(
                AuthMethod(user_id=user.id, auth_method=LoginPassword.__name__, value=row.value, param=row.param)
            )
        db_session.flush()
        return str(email_token)

    def login(self, db_session: DBSession, **kwargs) -> Session | None:
        if not (
                query := db_session.query(AuthMethod)
                        .filter(
                    AuthMethod.auth_method == self.__class__.__name__,
                    AuthMethod.param == "email",
                    AuthMethod.value == self.email.value,
                )
                        .one_or_none()
        ):
            raise AuthFailed(error="Incorrect login or password")
        secrets = {row.param: row.value for row in query.user.get_auth_methods(self.__class__.__name__)}
        if not secrets.get("is_active"):
            raise AuthFailed(error="Registration wasn't completed. Try to registrate again and approve your email")
        if (
                secrets.get(self.email.param) != self.email.value
                or secrets.get(self.hashed_password.param) != self.hashed_password.value
        ):
            raise AuthFailed(error="Incorrect login or password")
        db_session.add(session := Session(user_id=query.user.id, token=str(uuid4())))
        db_session.flush()
        return session

    @staticmethod
    def change_params(token: str, db_session: DBSession,
                      new_email: str | None = None, new_password: str | None = None) -> None:
        session: Session = db_session.query(Session).filter(Session.token == token).one_or_none()
        if session.expired:
            raise AuthFailed(error="Session expired, log in system again")
        for row in session.user.get_auth_methods(LoginPassword.__name__):
            match row.param:
                case "email":
                    row.value = new_email or row.param
                case "hashed_password":
                    salt = get_salt()
                    row.value = LoginPassword.__hash_password(new_password, salt)
        db_session.flush()
        return None

    @staticmethod
    def forgot_password():
        pass
