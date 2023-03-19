from .auth_method import AuthMethodMeta, AUTH_METHODS
from .email import Email
from .google import GoogleAuth
from .physics import PhysicsAuth
from .lkmsu import LkmsuAuth
from .yandex import YandexAuth
from .mymsu import MyMsuAuth
from .telegram import TelegramAuth
from .vk import VkAuth
from .github import GithubAuth


__all__ = [
    "AUTH_METHODS",
    "AuthMethodMeta",
    "Email",
    "GoogleAuth",
    "PhysicsAuth",
    "LkmsuAuth",
    "YandexAuth",
    "MyMsuAuth",
    "TelegramAuth",
    "VkAuth",
    "GithubAuth",
]
