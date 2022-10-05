from .auth_interface import AuthInterface
from auth_backend.models import Session


class LoginPassword(AuthInterface):

    email: str
    hashed_password: str
    salt: str

    def register(self) -> Session | None:
        pass

    def login(self) -> Session | None:
        pass

    def logout(self) -> None:
        pass

    def change_params(self) -> Session | None:
        pass

    def forgot_password(self) -> Session | None:
        pass
