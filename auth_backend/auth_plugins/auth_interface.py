from abc import ABCMeta

from auth_backend.models import Session


class AuthInterface(metaclass=ABCMeta):
    """
    Parameters:
        auth_params which auth type need: like email, hashed_password and salt
    """

    def register(self) -> Session | None:
        raise NotImplementedError()

    def login(self) -> Session | None:
        raise NotImplementedError()

    def logout(self) -> None:
        raise NotImplementedError()

    def forgot_password(self) -> Session | None:
        raise NotImplementedError()
