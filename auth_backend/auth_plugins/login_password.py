import datetime
import random
import string
from dataclasses import dataclass

from .auth_interface import AuthInterface
from sqlalchemy.orm import Session as DBSession
from auth_backend.models import Session, User, AuthMethod
import hashlib
from uuid import uuid4


def get_salt() -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(12)])


class LoginPassword(AuthInterface):
    @dataclass
    class Password(AuthInterface.Prop):
        salt: str | None

        def __init__(self, salt: str | None = None):
            super().__init__(datatype=str)
            self.salt = salt

        def __hash_password(self, password: str):
            salt = self.salt or get_salt()
            enc = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
            return enc.hex()

        def set_value(self, value: str, *, salt: str = None):
            if not isinstance(value, self.datatype):
                raise TypeError(f"Expected {self.datatype}, got {value} with type {type(value)}")
            self.value = LoginPassword.Password.__hash_password(value, salt)
            return self.value

        @staticmethod
        def validate_password(password: str, hashed_password: str):
            salt, hashed = hashed_password.split("$")
            return LoginPassword.Password.__hash_password(password, salt) == hashed

    email = AuthInterface.Prop(str)
    salt = AuthInterface.Prop(str)
    hashed_password = Password()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def register(self, db_session: DBSession, *, user_id: int | None = None) -> Session | None:
        if db_session.query(AuthMethod).filter(AuthMethod.auth_method == self.__class__.__name__,
                                               AuthMethod.param == "email",
                                               AuthMethod.value == self.email).one_or_none():
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
            db_session.add(AuthMethod(user_id=user.id, auth_method=attr.__class__.__name__, value=str(attr.value),
                                      param=attr.name))
        db_session.add(session := Session(token=str(uuid4()), user_id=user.id))
        db_session.flush()
        return session

    def login(self, db_session: DBSession, **kwargs) -> Session | None:
        check_existing: AuthMethod = db_session.query(AuthMethod).filter(
            AuthMethod.auth_method == self.__class__.__name__,
            AuthMethod.param == "email",
            AuthMethod.value == self.email).one_or_none()
        if not check_existing:
            raise Exception
        secrets = {row.name: row.value for row in
                   db_session.query(AuthMethod).filter(AuthMethod.user_id == check_existing.user.id,
                                                       AuthMethod.auth_method == self.__class__.__name__).all()}
        if secrets.get("email") != self.email or not LoginPassword.Password.validate_password(str(self.hashed_password),
                                                                                              secrets.get(
                                                                                                      "hashed_password")):
            raise Exception
        db_session.add(session := Session(user_id=check_existing.user.id, token=str(uuid4())))
        db_session.flush()
        return session

    def logout(self, db_session: DBSession, *, token: str = None) -> None:
        session: Session = db_session.query(Session).filter(Session.token == token).one_or_none()
        if not session:
            raise Exception
        if session.expires <= datetime.datetime.utcnow():
            raise Exception
        session.expires = datetime.datetime.utcnow()
        db_session.flush()
        return None

    def change_params(self, session: DBSession) -> Session | None:
        pass

    def forgot_password(self, session: DBSession) -> Session | None:
        pass
