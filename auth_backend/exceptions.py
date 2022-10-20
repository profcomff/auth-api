class ObjectNotFound(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__} {obj_id=} not found")


class AlreadyExists(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__}, {obj_id=} already exists")


class IncorrectAuthType(Exception):
    def __init__(self):
        super().__init__(f"Incorrect Authentication Type")


class AuthFailed(Exception):
    def __init__(self, error: str):
        super().__init__(error)