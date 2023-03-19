from __future__ import annotations

import re
from abc import ABCMeta

from auth_backend.models.db import AuthMethod


class MethodMeta(metaclass=ABCMeta):

    def __init__(self, methods: list[AuthMethod]):
        for method in methods:
            setattr(self, method.param, method)

    @classmethod
    def get_name(cls) -> str:
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

