from auth_backend.models.db import AuthMethod, User

from .auth_method import MethodMeta
from .email import Email
from .github import GithubAuth
from .google import GoogleAuth
from .lkmsu import LkmsuAuth
from .mymsu import MyMsuAuth
from .physics import PhysicsAuth
from .telegram import TelegramAuth
from .vk import VkAuth
from .yandex import YandexAuth


class MethodsDict:
    """Доступные методы авторизации пользователя

    Как это использовать? Когда создаете новый метод авторизации,
    определите около класса метода класс с именем `{название класса метода авторизации}Params`,
    наследника MethodMeta. Например:
    ```
    class EmailParams:
        pass
    ```

    Подробно про MethodMeta можно посмотреть в документации MethodMeta.

    Определите в классе авторизации ссылку `fields = тому классу, который вы создали`.
    Далее добавляете в MethodsDict поле, имя которого это название метода авторизации,
    определите его с дефлотным значением None,
    поставьте тайп хинт `{__repr__ класса метода авторизации}.fields}. Например:
    ```
    class MethodsDict:
        ...
        your_auth: YourAuth.fields = None
    ```

    Примеры использования:
    ```
    email = user.auth_methods.email.email.value

    user.auth_methods.email.tmp_token.is_deleted = True
    session.commit()

    user.auth_methods.email.create('tmp_token', random_string())

    user.auth_methods.email.bulk_create({"email": value})
    ```

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
        for Method in MethodMeta.__subclasses__():
            if Method.get_auth_method_name() not in _methods_dict.keys():
                _obj = Method(user=obj.__user)
                setattr(obj, Method.get_auth_method_name(), _obj)
                continue
            _obj = Method(methods=_methods_dict[Method.get_auth_method_name()], user=obj.__user)
            setattr(obj, Method.get_auth_method_name(), _obj)
        return obj
