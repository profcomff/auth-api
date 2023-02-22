class ObjectNotFound(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__} {obj_id=} not found")


class AlreadyExists(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__}, {obj_id=} already exists")


class IncorrectUserAuthType(Exception):
    def __init__(self):
        super().__init__(f"Incorrect Authentication Type for this user")


class SessionExpired(Exception):
    def __init__(self, token: str):
        super().__init__(f"Session that matches {token} expired")


class AuthFailed(Exception):
    def __init__(self, error: str):
        super().__init__(error)


class OauthAuthFailed(Exception):
    def __init__(self, error: str, id_token: str | None = None):
        self.id_token = id_token
        super().__init__(error)


class OauthCredentialsIncorrect(Exception):
    def __init__(self, error: str):
        super().__init__(error)
