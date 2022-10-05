import random
import string
from dataclasses import dataclass

from .auth_interface import AuthInterface
from sqlalchemy.orm import Session as ORMSession
from auth_backend.models import Session, User, AuthMethod

get_salt = lambda: "".join([random.choice(string.ascii_letters) for row in range(32)])


class LoginPassword(AuthInterface):

    @dataclass
    class Password(AuthInterface.Prop):
        def set_value(self, value):
            import hashlib
            if not isinstance(value, self.datatype):
                raise TypeError(f"Expected {self.datatype}, got {value} with type {type(value)}")
            self.value = hashlib.sha224(value.encode()).hexdigest()
            return self.value

    email = AuthInterface.Prop(str)
    salt = AuthInterface.Prop(str)
    hashed_password = Password()



    # def register(self, user_id: int,* ,session: ORMSession) -> Session | None:
    #     if session.query(AuthMethod).filter(AuthMethod.auth_method == "email", AuthMethod.value == self.email).all()
    #         raise Exception


    def login(self, session: ORMSession) -> Session | None:
        pass

    def logout(self, session: ORMSession) -> None:
        pass

    def change_params(self, session: ORMSession) -> Session | None:
        pass

    def forgot_password(self, session: ORMSession) -> Session | None:
        pass
