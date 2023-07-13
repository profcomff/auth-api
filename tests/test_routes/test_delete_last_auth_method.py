import asyncio
import errno
import random
import string

import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from auth_backend.auth_plugins import Email, YandexAuth
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.exceptions import LastAuthMethodDelete
from auth_backend.models import AuthMethod, User
from auth_backend.settings import Settings, get_settings


pytest_plugins = ('pytest_asyncio',)

settings = get_settings()


@pytest.mark.asyncio
async def test_delete_method(yandex_user, dbsession):
    with pytest.raises(LastAuthMethodDelete):
        await YandexAuth._delete_auth_methods(yandex_user, db_session=dbsession)
