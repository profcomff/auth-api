from fastapi import APIRouter, HTTPException, Depends
from fastapi_sqlalchemy import db
from pydantic import parse_obj_as

from auth_backend.base import ResponseModel
from auth_backend.models.db import UserSession, Scope
from auth_backend.routes.models.models import ScopeGet, ScopePost, ScopePatch
from auth_backend.utils.security import UnionAuth

auth = UnionAuth()

scopes = APIRouter(prefix="/scopes", tags=["Scopes"])

@scopes.post("", response_model=ScopeGet)
async def create_scope(scope: ScopePost, _: UserSession = Depends(auth)) -> ScopeGet:
    if Scope.query(session=db.session).filter(Scope.name == scope.name).all():
        raise HTTPException(status_code=409, detail=ResponseModel(status="Error", message="Already exists").json())
    return ScopeGet.from_orm(Scope.create(**scope.dict(), session=db.session))

@scopes.get("/{id}", response_model=ScopeGet)
async def get_scope(id: int, _: UserSession = Depends(auth)) -> ScopeGet:
    return ScopeGet.from_orm(Scope.get(id, session=db.session))

@scopes.get("", response_model=list[ScopeGet])
async def get_scopes(_: UserSession = Depends(auth)) -> list[ScopeGet]:
    return parse_obj_as(list[ScopeGet], Scope.query(session=db.session).all())

@scopes.patch("/{id}", response_model=ScopeGet)
async def update_scope(id: int, scope_inp: ScopePatch,  _: UserSession = Depends(auth)) -> ScopeGet:
    scope = Scope.get(id, session=db.session)
    return ScopeGet.from_orm(Scope.update(scope.id, **scope_inp.dict(), session=db.session))


@scopes.delete("/{id}", response_model=ResponseModel)
async def delete_scope(id: int, _: UserSession = Depends(auth)):
    return Scope.delete(session=db.session, id=id)
