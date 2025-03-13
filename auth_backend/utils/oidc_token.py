from datetime import datetime
from enum import Enum

from fastapi import BackgroundTasks
from fastapi_sqlalchemy import db

from auth_backend.auth_plugins.email import Email
from auth_backend.exceptions import AuthFailed, SessionExpired
from auth_backend.models.db import Scope, UserSession
from auth_backend.schemas.models import Session as SessionSchema
from auth_backend.utils.user_session_control import SESSION_UPDATE_SCOPE, create_session


class OidcGrantType(str, Enum):
    authorization_code = 'authorization_code'
    refresh_token = 'refresh_token'
    client_credentials = 'client_credentials'


async def token_by_refresh_token(
    refresh_token: str | None,
    requested_scopes: list[str] | None,
) -> SessionSchema:
    # Все токены автоматически считаем refresh-токенами
    if not refresh_token:
        raise TypeError("refresh_token required for refresh_token grant_type ")
    old_session: UserSession = (
        UserSession.query(session=db.session).filter(UserSession.token == refresh_token).one_or_none()
    )
    if not old_session or old_session.expired:
        raise SessionExpired()

    # Продлеваем только те токены, которые явно разрешено продлевать
    # Остальные просто заменяем на новые с тем же сроком действия
    session_scopes = old_session.user.scope_names if old_session.is_unbounded else old_session.scope_names

    # Если запрошены скоупы, то выдать новый токен с запрошенными скоупами, если у текущего хватает прав
    if requested_scopes:
        requested_scopes = set(requested_scopes)
        if requested_scopes > session_scopes:
            not_found_scopes = ', '.join(session_scopes - requested_scopes)
            raise AuthFailed("Can't get scopes: " + not_found_scopes, "Невозможно получить права: " + not_found_scopes)
        session_scopes = requested_scopes

    # Продлить действие токена, если сессия это позволяет
    expire_ts = None
    if SESSION_UPDATE_SCOPE not in session_scopes:
        expire_ts = old_session.expires

    new_session = await create_session(
        old_session.user,
        session_scopes,
        expire_ts,
        old_session.session_name,
        old_session.is_unbounded,
        db_session=db.session,
    )

    # Старую сессию убиваем
    old_session.expires = datetime.utcnow()
    db.session.commit()

    return new_session


async def token_by_client_credentials(
    username: str | None,
    password: str | None,
    scopes: list[str] | None,
    user_agent: str,
    background_tasks: BackgroundTasks,
) -> SessionSchema:
    if not username or not password:
        raise AuthFailed("Incorrect login or password", "Некорректный логин или пароль")

    return await Email.login(
        username,
        password,
        Scope.get_by_names(scopes, session=db.session),
        session_name=user_agent,
        background_tasks=background_tasks,
    )
