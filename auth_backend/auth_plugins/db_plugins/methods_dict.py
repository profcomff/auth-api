from .lkmsu import LkmsuAuth
from .google import GoogleAuth
from .physics import PhysicsAuth
from .email import Email
from auth_backend.models.db import AuthMethod
from .db_aggregators_meta import MethodMeta


class MethodsDict:
    email: Email
    google_auth: GoogleAuth
    physics_auth: PhysicsAuth
    lkmsu_auth: LkmsuAuth

    def __new__(cls, methods: list[AuthMethod], *args, **kwargs):
        obj = super(MethodsDict, cls).__new__(cls)
        _methods_dict: dict[str, list[AuthMethod]] = {}
        for method in methods:
            if method.auth_method not in _methods_dict.keys():
                _methods_dict[method.auth_method] = []
            _methods_dict[method.auth_method].append(method)
        for Method in MethodMeta.__subclasses__():
            if Method.get_name() not in _methods_dict.keys():
                continue
            _obj = Method(_methods_dict[Method.get_name()])
            setattr(obj, Method.get_name(), _obj)
        return obj
