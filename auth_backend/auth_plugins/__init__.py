from .auth_method import AuthMethodMeta, AUTH_METHODS
from .email import Email
from .google import GoogleAuth
from .physics import PhysicsAuth
from .lkmsu import LkmsuAuth
from .yandex import YandexAuth

__all__ = ["AUTH_METHODS", "AuthMethodMeta", "Email"]
