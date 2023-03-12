from fastapi import APIRouter, HTTPException, Depends
from fastapi_sqlalchemy import db
from pydantic import parse_obj_as
from sqlalchemy import func

from auth_backend.base import ResponseModel
from auth_backend.models.db import UserSession, Scope
from auth_backend.pydantic.models import ScopeGet, ScopePost, ScopePatch
from auth_backend.utils.security import UnionAuth


scopes = APIRouter(prefix="/scope", tags=["Scopes"])


@scopes.post("", response_model=ScopeGet)
async def create_scope(
    scope: ScopePost,
    user_session: UserSession = Depends(UnionAuth(scopes=["auth.scope.create"], allow_none=False, auto_error=True)),
) -> ScopeGet:
    if Scope.query(session=db.session).filter(func.lower(Scope.name) == scope.name.lower()).all():
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Already exists").json())
    scope.name = scope.name.lower()
    return ScopeGet.from_orm(Scope.create(**scope.dict(), creator_id=user_session.user_id, session=db.session))


@scopes.get("/{id}", response_model=ScopeGet)
async def get_scope(
    id: int, _: UserSession = Depends(UnionAuth(scopes=["auth.scope.read"], allow_none=False, auto_error=True))
) -> ScopeGet:
    return ScopeGet.from_orm(Scope.get(id, session=db.session))


@scopes.get("", response_model=list[ScopeGet])
async def get_scopes(
    _: UserSession = Depends(UnionAuth(scopes=["auth.scope.read"], allow_none=False, auto_error=True))
) -> list[ScopeGet]:
    return parse_obj_as(list[ScopeGet], Scope.query(session=db.session).all())


@scopes.patch("/{id}", response_model=ScopeGet)
async def update_scope(
    id: int,
    scope_inp: ScopePatch,
    _: UserSession = Depends(UnionAuth(scopes=["auth.scope.update"], allow_none=False, auto_error=True)),
) -> ScopeGet:
    scope = Scope.get(id, session=db.session)
    return ScopeGet.from_orm(Scope.update(scope.id, **scope_inp.dict(), session=db.session))


@scopes.delete("/{id}", response_model=ResponseModel)
async def delete_scope(
    id: int, _: UserSession = Depends(UnionAuth(scopes=["auth.scope.delete"], allow_none=False, auto_error=True))
):
    Scope.delete(session=db.session, id=id)
    return ResponseModel(status="Success", message="Scope has been deleted")
