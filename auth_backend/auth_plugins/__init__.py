from auth_backend.auth_method import AUTH_METHODS, AuthPluginMeta

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
from .postgres import PostgresOuterAuth
from .coder import CoderOuterAuth
from .airflow import AirflowOuterAuth


__all__ = [
    "AUTH_METHODS",
    "AuthPluginMeta",
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
    "PostgresOuterAuth",
    "CoderOuterAuth",
    "AirflowOuterAuth",
]
