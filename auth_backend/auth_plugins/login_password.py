import hashlib
import random
import string
from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy.orm import Session as DBSession, Session as ORMSession

from auth_backend.models import Session, User, AuthMethod
from .auth_interface import AuthInterface


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class LoginPassword(AuthInterface):
    @staticmethod
    def change_params(token: str, db_session: ORMSession, **kwargs) -> None:
        session: Session = db_session.query(Session).filter(Session.token == token).one_or_none()
        if session.expired():
            raise Exception
        for row in session.user.get_auth_methods(LoginPassword.__name__):
            if row.param in kwargs.keys():
                row.value = kwargs[row.param]
        db_session.flush()
        return None

    @dataclass
    class Password(AuthInterface.Prop):
        salt: str | None

        def __init__(self, salt: str | None = None):
            super().__init__(datatype=str)
            self.salt = salt

        @staticmethod
        def __hash_password(password: str, salt: str):
            enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
            return enc.hex()

        def set_value(self, value: str, **kwargs):
            if not isinstance(value, self.datatype):
                raise TypeError(f"Expected {self.datatype}, got {value} with type {type(value)}")
            self.value = LoginPassword.Password.__hash_password(value, self.salt)
            return self.value

        @staticmethod
        def validate_password(password: str, hashed_password: str):
            salt, hashed = hashed_password.split("$")
            return LoginPassword.Password.__hash_password(password, salt) == hashed

    email: AuthInterface.Prop = AuthInterface.Prop(str)
    salt: AuthInterface.Prop
    hashed_password: Password

    def __init__(self, db_session: DBSession, **kwargs):
        if "email" not in kwargs.keys():
            raise Exception
        salt: str = None
        ## FIXME
        if query := db_session.query(AuthMethod).filter(AuthMethod.value == kwargs.get("email")).one_or_none():
            for row in query.user.get_auth_methods(self.__class__.__name__):
                if row.param == "salt":
                    salt = row.value
        else:
            salt = get_salt()
        self.salt = AuthInterface.Prop(str)
        self.salt.set_value(salt)
        self.hashed_password = LoginPassword.Password(str(self.salt.value))
        super().__init__(**kwargs)

    def register(self, db_session: DBSession, *, user_id: int | None = None) -> Session | None:
        if (
            db_session.query(AuthMethod)
            .filter(
                AuthMethod.auth_method == self.__class__.__name__,
                AuthMethod.param == "email",
                AuthMethod.value == self.email,
            )
            .one_or_none()
        ):
            raise Exception
        if not user_id:
            db_session.add(user := User())
        else:
            user = db_session.query(User).get(user_id)
        if not user:
            raise Exception
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if not isinstance(attr, AuthInterface.Prop):
                continue
            db_session.add(
                AuthMethod(user_id=user.id, auth_method=attr.__class__.__name__, value=str(attr.value), param=attr.name)
            )
        db_session.add(session := Session(token=str(uuid4()), user_id=user.id))
        db_session.flush()
        return session

    def login(self, db_session: DBSession, **kwargs) -> Session | None:
        check_existing: AuthMethod = (
            db_session.query(AuthMethod)
            .filter(
                AuthMethod.auth_method == self.__class__.__name__,
                AuthMethod.param == "email",
                AuthMethod.value == self.email,
            )
            .one_or_none()
        )
        if not check_existing:
            raise Exception
        secrets = {row.name: row.value for row in check_existing.user.get_auth_methods(self.__class__.__name__)}
        if secrets.get("email") != self.email or not LoginPassword.Password.validate_password(
            str(self.hashed_password), secrets.get("hashed_password")
        ):
            raise Exception
        db_session.add(session := Session(user_id=check_existing.user.id, token=str(uuid4())))
        db_session.flush()
        return session

    @staticmethod
    def forgot_password():
        pass
