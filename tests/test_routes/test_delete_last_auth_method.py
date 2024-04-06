import pytest

from auth_backend.auth_plugins import YandexAuth
from auth_backend.exceptions import LastAuthMethodDelete
from auth_backend.settings import get_settings


pytest_plugins = ('pytest_asyncio',)

settings = get_settings()


@pytest.mark.asyncio
async def test_delete_method(yandex_user, dbsession):
    with pytest.raises(LastAuthMethodDelete):
        await YandexAuth._delete_auth_methods(yandex_user, db_session=dbsession)
