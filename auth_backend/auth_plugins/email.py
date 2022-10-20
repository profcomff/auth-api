from .auth_method import AuthMethod


class Email(AuthMethod):
    FIELDS = ["email", "hashed_password", "salt", "confirmed", "confirmation_token", "reset_token"]

    async def login_flow(self, **kwargs):
        pass

    def __init__(self):
        super().__init__()

    async def register_flow(self, **kwargs):
        pass

    async def change_params(self):
        pass


