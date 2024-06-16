from typing import TYPE_CHECKING, Iterable

from auth_backend.settings import get_settings


if TYPE_CHECKING:
    from auth_backend.auth_plugins.auth_method import AuthMethodMeta

settings = get_settings()


def is_method_active(method: type[AuthMethodMeta]) -> bool:
    return settings.ENABLED_AUTH_METHODS is None or method.get_name() in settings.ENABLED_AUTH_METHODS


def active_auth_methods() -> Iterable[type[AuthMethodMeta]]:
    from auth_backend.auth_plugins.auth_method import AUTH_METHODS
    for method in AUTH_METHODS.values():
        if settings.ENABLED_AUTH_METHODS is None or method.get_name() in settings.ENABLED_AUTH_METHODS:
            yield method
