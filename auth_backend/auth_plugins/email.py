from .auth_method import AuthMethod
from sqlalchemy.orm import Session
from auth_backend.models.db import UserSession


class Email(AuthMethod):
    FIELDS = ["email", "hashed_password", "salt", "confirmed", "confirmation_token", "reset_token"]

    async def login_flow(self, *, session: Session) -> UserSession:
        pass

    def __init__(self):
        super().__init__()

    async def register_flow(self, *, session: Session) -> str:
        pass

    async def change_params(self):
        pass


