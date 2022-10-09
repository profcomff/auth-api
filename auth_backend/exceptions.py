

class ObjectNotFound(Exception):
    def __init__(self, obj: type, obj_id: int):
        super().__init__(f"Object {obj.__name__} {obj_id=} not found")
