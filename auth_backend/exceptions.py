class ObjectNotFound(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__} {obj_id=} not found")


class IncorrectLoginOrPassword(Exception):
    def __init__(self):
        super().__init__(f"Login or password is incorrect")


class AlreadyExists(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__}, {obj_id=} already exists")


class SessionExpired(Exception):
    def __init__(self):
        super().__init__(f"Session expired, login one more time")


class IncorrectAuthType(Exception):
    def __init__(self):
        super().__init__(f"Incorrect Authentication Type")
