import datetime


class AuthAPIError(Exception):
    eng: str
    ru: str

    def __init__(self, eng: str, ru: str) -> None:
        self.eng = eng
        self.ru = ru
        super().__init__(eng)


class ObjectNotFound(AuthAPIError):
    def __init__(self, obj: type, obj_id_or_name: int | str):
        super().__init__(
            f"Object {obj.__name__} {obj_id_or_name=} not found",
            f"Объект {obj.__name__}  с идентификатором {obj_id_or_name} не найден",
        )


class AlreadyExists(AuthAPIError):
    def __init__(self, obj: type, obj_id_or_name: int | str):
        super().__init__(
            f"Object {obj.__name__}, {obj_id_or_name=} already exists",
            f"Объект {obj.__name__} с идентификатором {obj_id_or_name=} уже существует",
        )


class IncorrectUserAuthType(AuthAPIError):
    def __init__(self):
        super().__init__("Incorrect Authentication Type for this user", "Некорректный тип аутентификации")


class SessionExpired(AuthAPIError):
    def __init__(self, token: str = ""):
        super().__init__(
            f"Session that matches expired or not exists",
            f"Срок действия токена истёк или токен не существует",
        )


class AuthFailed(AuthAPIError):
    def __init__(self, error_eng: str, error_ru: str):
        super().__init__(error_eng, error_ru)


class OauthAuthFailed(AuthAPIError):
    def __init__(self, error_eng: str, error_ru: str, id_token: str | None = None, status_code=401):
        self.id_token = id_token
        self.status_code = status_code
        super().__init__(error_eng, error_ru)


class OauthCredentialsIncorrect(AuthAPIError):
    def __init__(self, error_eng: str, error_ru: str):
        super().__init__(error_eng, error_ru)


class TooManyEmailRequests(AuthAPIError):
    delay_time: datetime.timedelta

    def __init__(self, dtime: datetime.timedelta):
        self.delay_time = dtime
        super().__init__(
            f'Too many email requests. Delay: {dtime}',
            f'Слишком много запросов к email. Задержка: {dtime}',
        )


class LastAuthMethodDelete(AuthAPIError):
    def __init__(self):
        super().__init__('Unable to remove last authentication method', 'Нельзя удалить последний метод входа')
