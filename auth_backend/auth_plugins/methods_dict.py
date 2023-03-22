from auth_backend.models.db import AuthMethod, User
from .auth_method import AuthMethodMeta
from .email import Email
from .google import GoogleAuth
from .lkmsu import LkmsuAuth
from .physics import PhysicsAuth
from .mymsu import MyMsuAuth
from .yandex import YandexAuth
from .github import GithubAuth
from .telegram import TelegramAuth
from .vk import VkAuth


class MethodsDict:
    __user: User
    email: Email.fields = Email.fields
    google_auth: GoogleAuth.fields = GoogleAuth.fields
    physics_auth: PhysicsAuth.fields = PhysicsAuth.fields
    lkmsu_auth: LkmsuAuth.fields = LkmsuAuth.fields
    my_msu_auth: MyMsuAuth.fields = MyMsuAuth.fields
    telegram_auth: TelegramAuth.fields = TelegramAuth.fields
    vk_auth: VkAuth.fields = VkAuth.fields
    github_auth: GithubAuth.fields = GithubAuth.fields
    yandex_auth: YandexAuth.fields = YandexAuth.fields


    def __new__(cls, methods: list[AuthMethod], user: User, *args, **kwargs):
        obj = super(MethodsDict, cls).__new__(cls)
        obj.__user = user
        _methods_dict: dict[str, list[AuthMethod]] = {}
        for method in methods:
            if method.auth_method not in _methods_dict.keys():
                _methods_dict[method.auth_method] = []
            _methods_dict[method.auth_method].append(method)
        for Method in AuthMethodMeta.MethodMeta.__subclasses__():
            if Method.get_name() not in _methods_dict.keys():
                continue
            _obj = Method(_methods_dict[Method.get_name()],  user=obj.__user)
            setattr(obj, Method.get_name(), _obj)
        return obj

