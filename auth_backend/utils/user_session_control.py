import random
import string
from datetime import datetime, timedelta

from fastapi import HTTPException
from fastapi_sqlalchemy import db
from sqlalchemy.orm import Session as DbSession

from auth_backend.base import Logout
from auth_backend.models.db import Scope, User, UserSession, UserSessionScope
from auth_backend.schemas.models import Session
from auth_backend.schemas.types.scopes import Scope as TypeScope
from auth_backend.settings import Settings, get_settings


settings = get_settings()


def random_string(length: int = 32) -> str:
    return "".join([random.choice(string.ascii_letters) for _ in range(length)])


async def create_session(
    user: User, scopes_list_names: list[TypeScope] | None, expires: datetime = None, *, db_session: DbSession
) -> Session:
    """Создает сессию пользователя"""
    scopes = set()
    if scopes_list_names is None:
        scopes = user.scopes
    else:
        scopes = await create_scopes_set_by_names(scopes_list_names)
        await check_scopes(scopes, user)
    user_session = UserSession(user_id=user.id, token=random_string(length=settings.TOKEN_LENGTH))
    user_session.expires = expires or user_session.expires
    db_session.add(user_session)
    db_session.flush()
    for scope in scopes:
        db_session.add(UserSessionScope(scope_id=scope.id, user_session_id=user_session.id))
    db_session.commit()
    return Session(
        user_id=user_session.user_id,
        token=user_session.token,
        id=user_session.id,
        expires=user_session.expires,
        session_scopes=[_scope.name for _scope in user_session.scopes],
    )


async def create_scopes_set_by_names(scopes_list_names: list[TypeScope]) -> set[Scope]:
    """Создает множество скоупов из списка"""
    scopes = set()
    for scope_name in scopes_list_names:
        scope = Scope.get_by_name(scope_name, session=db.session)
        scopes.add(scope)
    return scopes


async def check_scopes(scopes: set[Scope], user: User) -> None:
    '''Проверяет, чтобы количество новых скоупов совпадало со старым количеством'''
    if len(scopes & user.scopes) != len(scopes):
        raise HTTPException(
            status_code=403,
            detail=Logout(
                status="Error",
                message=f"Incorrect user scopes, triggering scopes -> {[scope.name for scope in scopes - user.scopes]} ",
            ).dict(),
        )
