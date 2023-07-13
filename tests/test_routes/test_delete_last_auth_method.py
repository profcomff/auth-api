import asyncio
import errno

import pytest
import pytest_asyncio
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from auth_backend.auth_plugins import YandexAuth
from auth_backend.auth_plugins.auth_method import random_string
from auth_backend.exceptions import LastAuthMethodDelete
from auth_backend.models import AuthMethod, User
from auth_backend.settings import Settings, get_settings


pytest_plugins = ('pytest_asyncio',)

settings = get_settings()


def create_test_user(email: str, password: str, dbsession) -> User:
    if (
        AuthMethod.query(session=dbsession)
        .filter(AuthMethod.value == email, AuthMethod.auth_method == YandexAuth.get_name())
        .one_or_none()
    ):
        exit(errno.EIO)
    user = User.create(session=dbsession)
    dbsession.flush()
    email = AuthMethod.create(
        user_id=user.id, param="email", value=email, auth_method=YandexAuth.get_name(), session=dbsession
    )
    _salt = random_string()
    password = AuthMethod.create(
        user_id=user.id,
        param="hashed_password",
        value="///",
        auth_method=YandexAuth.get_name(),
        session=dbsession,
    )
    salt = AuthMethod.create(
        user_id=user.id, param="salt", value=_salt, auth_method=YandexAuth.get_name(), session=dbsession
    )
    confirmed = AuthMethod.create(
        user_id=user.id, param="confirmed", value="true", auth_method=YandexAuth.get_name(), session=dbsession
    )
    confirmation_token = AuthMethod.create(
        user_id=user.id, param="confirmation_token", value="admin", auth_method=YandexAuth.get_name(), session=dbsession
    )
    dbsession.add_all([email, password, salt, confirmed, confirmation_token])
    dbsession.commit()
    return user


@pytest.mark.asyncio
async def test_delete_method(dbsession):
    user = create_test_user("em@yandex.ru", "12345678", dbsession)
    with pytest.raises(LastAuthMethodDelete):
        await YandexAuth._delete_auth_methods(user, db_session=dbsession)
    dbsession.query(AuthMethod).filter(AuthMethod.user_id == user.id).delete()
    dbsession.query(User).filter(User.id == user.id).delete()
    dbsession.commit()
