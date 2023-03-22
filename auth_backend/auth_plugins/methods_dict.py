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
    """
    Как это использовать? Когда создаете новый метод авторизации,
    определите внутри класса метода класс с таким же именем, наследника
    MethodMeta. Там есть поля __fields__ - поля, которые вы создаете
    в таблице AuthMethod в колонке param, __required_fields__ -
    обязательные поля, при отсутствии которых можно считать, что у юзера
    нет этого способа входа. Эти поля определите как классовые переменные
    с дефолтным значением None. Определите в классе авторизации
    fields = тому классу, который вы создали.
    Далее добавляете в MethodsDict поле, алиас которого это то, что
    возвращает <созданный выше класс>.get_name(), определите его с дефлотным
    значением None, поставьте тайп хинт.

    Примеры:
    email = user.auth_methods.email.email.value

    user.auth_methods.email.tmp_token.is_deleted = True
    session.commit()

    user.auth_methods.email.create('tmp_token', random_string())

    user.auth_methods.email.bulk_create(k-v map)
    """
    __user: User
    email: Email.fields = None
    google_auth: GoogleAuth.fields = None
    physics_auth: PhysicsAuth.fields = None
    lkmsu_auth: LkmsuAuth.fields = None
    my_msu_auth: MyMsuAuth.fields = None
    telegram_auth: TelegramAuth.fields = None
    vk_auth: VkAuth.fields = None
    github_auth: GithubAuth.fields = None
    yandex_auth: YandexAuth.fields = None


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
                _obj = Method(user=obj.__user)
                setattr(obj, Method.get_name(), _obj)
                continue
            _obj = Method(methods=_methods_dict[Method.get_name()],  user=obj.__user)
            setattr(obj, Method.get_name(), _obj)
        return obj

