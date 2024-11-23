from datetime import datetime

from fastapi import HTTPException
from fastapi_sqlalchemy import db
from sqlalchemy.orm import Session as DbSession

from auth_backend.base import StatusResponseModel
from auth_backend.models.db import Scope, User, UserSession, UserSessionScope
from auth_backend.schemas.models import Session
from auth_backend.schemas.types.scopes import Scope as TypeScope
from auth_backend.settings import get_settings
from auth_backend.utils.string import random_string


settings = get_settings()


async def create_session(
    user: User,
    scopes_list_names: list[TypeScope] | None,
    expires: datetime | None = None,
    session_name: str | None = None,
    is_unbounded: bool | None = None,
    *,
    db_session: DbSession,
) -> Session:
    """Создает сессию пользователя"""
    if scopes_list_names is None:
        scopes = user.scopes
    else:
        scopes = await create_scopes_set_by_names(scopes_list_names)
        await check_scopes(scopes, user)
    user_session = UserSession(
        user_id=user.id, token=random_string(length=settings.TOKEN_LENGTH), session_name=session_name
    )
    user_session.expires = expires or user_session.expires
    user_session.is_unbounded = is_unbounded or user_session.is_unbounded
    db_session.add(user_session)
    db_session.flush()
    if not user_session.is_unbounded:
        for scope in scopes:
            db_session.add(UserSessionScope(scope_id=scope.id, user_session_id=user_session.id))
    db_session.commit()
    return Session(
        session_name=session_name,
        user_id=user_session.user_id,
        token=user_session.token,
        id=user_session.id,
        expires=user_session.expires,
        is_unbounded=user_session.is_unbounded,
        session_scopes=[_scope.name for _scope in user_session.scopes],
        last_activity=user_session.last_activity,
    )


async def create_scopes_set_by_names(scopes_list_names: list[TypeScope]) -> set[Scope]:
    """Создает множество скоупов из списка"""
    scopes = set()
    for scope_name in scopes_list_names:
        scope = Scope.get_by_name(scope_name, session=db.session)
        scopes.add(scope)
    return scopes


async def check_scopes(scopes: set[Scope], user: User) -> None:
    '''Проверяет доступность скоуппов для юзера'''
    if len(scopes & user.scopes) != len(scopes):
        raise HTTPException(
            status_code=403,
            detail=StatusResponseModel(
                status="Error",
                message=f"Incorrect user scopes, triggering scopes -> {[scope.name for scope in scopes - user.scopes]} ",
                ru=f"Не хватает прав, нужно -> {[scope.name for scope in scopes - user.scopes]}",
            ).model_dump(),
        )
