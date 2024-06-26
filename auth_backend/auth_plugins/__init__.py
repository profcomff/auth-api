from auth_backend.auth_method import AUTH_METHODS, AuthPluginMeta

from .airflow import AirflowOuterAuth
from .coder import CoderOuterAuth
from .email import Email
from .github import GithubAuth
from .google import GoogleAuth
from .keycloak import KeycloakAuth
from .lkmsu import LkmsuAuth
from .mailu import MailuOuterAuth
from .mymsu import MyMsuAuth
from .physics import PhysicsAuth
from .postgres import PostgresOuterAuth
from .telegram import TelegramAuth
from .vk import VkAuth
from .yandex import YandexAuth


__all__ = [
    "AUTH_METHODS",
    "AuthPluginMeta",
    # Основной провайдер
    "Email",
    # Oauth провайдеры
    "GoogleAuth",
    "PhysicsAuth",
    "LkmsuAuth",
    "YandexAuth",
    "MyMsuAuth",
    "TelegramAuth",
    "VkAuth",
    "GithubAuth",
    "KeycloakAuth",
    # Провайдеры синхронизации паролей
    "PostgresOuterAuth",
    "CoderOuterAuth",
    "AirflowOuterAuth",
    "MailuOuterAuth",
]
