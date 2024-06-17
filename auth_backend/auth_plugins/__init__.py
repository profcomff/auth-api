from auth_backend.auth_method import AUTH_METHODS, AuthMethodMeta

from .email import Email
from .github import GithubAuth
from .google import GoogleAuth
from .keycloak import KeycloakAuth
from .lkmsu import LkmsuAuth
from .mymsu import MyMsuAuth
from .physics import PhysicsAuth
from .telegram import TelegramAuth
from .vk import VkAuth
from .yandex import YandexAuth


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
    "KeycloakAuth",
]
