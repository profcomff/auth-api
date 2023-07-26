import datetime


class ObjectNotFound(Exception):
    def __init__(self, obj: type, obj_id_or_name: int | str):
        super().__init__(f"Object {obj.__name__} {obj_id_or_name=} not found")


class AlreadyExists(Exception):
    def __init__(self, obj: type, obj_id_or_name: int | str):
        super().__init__(f"Object {obj.__name__}, {obj_id_or_name=} already exists")


class IncorrectUserAuthType(Exception):
    def __init__(self):
        super().__init__("Incorrect Authentication Type for this user")


class SessionExpired(Exception):
    def __init__(self, token: str):
        super().__init__(f"Session that matches {token} expired")


class AuthFailed(Exception):
    def __init__(self, error: str):
        super().__init__(error)


class OauthAuthFailed(Exception):
    def __init__(self, error: str, id_token: str | None = None, status_code=401):
        self.id_token = id_token
        self.status_code = status_code
        super().__init__(error)


class OauthCredentialsIncorrect(Exception):
    def __init__(self, error: str):
        super().__init__(error)


class TooManyEmailRequests(Exception):
    delay_time: datetime.timedelta

    def __init__(self, dtime: datetime.timedelta):
        self.delay_time = dtime
        super().__init__(f'Delay: {dtime}')


class LastAuthMethodDelete(Exception):
    def __init__(self):
        super().__init__(f'Unable to remove last authentication method')
