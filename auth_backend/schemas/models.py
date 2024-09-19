from __future__ import annotations

from datetime import datetime
from typing import Annotated

from annotated_types import Gt, MinLen
from pydantic import field_validator

from auth_backend.base import Base
from auth_backend.schemas.types.scopes import Scope


class PinchedScope(Base):
    id: int
    name: Scope


class Group(Base):
    id: Annotated[int, Gt(0)]
    name: str
    parent_id: Annotated[int, Gt(0)] | None = None


class GroupScopes(Base):
    scopes: list[PinchedScope] | None = None


class GroupChilds(Base):
    child: list[Group] | None = None


class GroupIndirectScopes(Base):
    indirect_scopes: list[PinchedScope] | None = None


class GroupUserList(Base):
    users: list[int] | None = None


class GroupGet(Group, GroupChilds, GroupIndirectScopes, GroupScopes, GroupUserList):
    pass


class User(Base):
    id: int


class UserInfo(User):
    email: str | None = None


class UserGroups(Base):
    groups: list[int] | None = None


class UserIndirectGroups(Base):
    indirect_groups: list[int] | None = None


class UserScopes(Base):
    user_scopes: list[PinchedScope] | None = None


class UserAuthMethods(Base):
    auth_methods: list[str] | None = None


class SessionScopes(Base):
    session_scopes: list[PinchedScope] | None = None


class UserGet(UserInfo, UserGroups, UserIndirectGroups, UserScopes, SessionScopes, UserAuthMethods):
    pass


class UsersGet(Base):
    items: list[UserGet]


class UserPatch(Base):
    groups: list[int]


class GroupPost(Base):
    name: str
    parent_id: Annotated[int, Gt(0)] | None = None
    scopes: list[int]


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None = None
    parent_id: Annotated[int, Gt(0)] | None = None
    scopes: list[int] | None = None


class UserGroupGet(Base):
    group_id: Annotated[int, Gt(0)]
    user_id: Annotated[int, Gt(0)]


class UserGroupPost(Base):
    user_id: Annotated[int, Gt(0)]


class GroupUserListGet(Base):
    items: list[UserInfo]


class ScopeGet(Base):
    id: int
    name: Scope
    comment: str | None = None


class ScopePost(Base):
    name: Scope
    comment: str | None = None


class ScopePatch(Base):
    name: Scope | None = None
    comment: str | None = None


class Session(Base):
    session_name: str | None = None
    token: Annotated[str, MinLen(1)] | None = None
    expires: datetime | None = None
    id: int
    user_id: int
    is_unbounded: bool | None = None
    session_scopes: list[Scope] | None = None
    last_activity: datetime


class SessionPost(Base):
    session_name: str | None = None
    scopes: list[Scope] = []
    expires: datetime | None = None
    is_unbounded: bool | None = None

    @classmethod
    @field_validator("expires")
    @classmethod
    def expires_validator(cls, exp):
        if exp < datetime.utcnow():
            raise ValueError()
        return exp


class SessionPatch(Base):
    session_name: str | None = None
    scopes: list[Scope] | None = None


Group.model_rebuild()
GroupGet.model_rebuild()
UserScopes.model_rebuild()
UserGet.model_rebuild()
SessionScopes.model_rebuild()
