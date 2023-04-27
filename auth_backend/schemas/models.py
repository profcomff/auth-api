from __future__ import annotations

from datetime import datetime

from pydantic import Field, constr, validator

from auth_backend.base import Base
from auth_backend.schemas.types.scopes import Scope


class PinchedScope(Base):
    id: int
    name: Scope


class Group(Base):
    id: int = Field(..., gt=0)
    name: str
    parent_id: int | None = Field(None, gt=0)


class GroupScopes(Base):
    scopes: list[PinchedScope] | None


class GroupChilds(Base):
    child: list[Group] | None


class GroupIndirectScopes(Base):
    indirect_scopes: list[PinchedScope] | None


class GroupUserList(Base):
    users: list[int] | None


class GroupGet(Group, GroupChilds, GroupIndirectScopes, GroupScopes, GroupUserList):
    pass


class UserInfo(Base):
    id: int
    email: str | None


class UserGroups(Base):
    groups: list[int] | None


class UserIndirectGroups(Base):
    indirect_groups: list[int] | None


class UserScopes(Base):
    user_scopes: list[PinchedScope] | None


class UserAuthMethods(Base):
    auth_methods: list[str] | None


class SessionScopes(Base):
    session_scopes: list[PinchedScope] | None


class UserGet(UserInfo, UserGroups, UserIndirectGroups, UserScopes, SessionScopes, UserAuthMethods):
    pass


class UsersGet(Base):
    items: list[UserGet]

    class Config:
        fields = {'session_scopes': {'exclude': True}}


class UserPatch(Base):
    groups: list[int]


class GroupPost(Base):
    name: str
    parent_id: int | None = Field(None, gt=0)
    scopes: list[int]


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None
    parent_id: int | None = Field(None, gt=0)
    scopes: list[int] | None


class UserGroupGet(Base):
    group_id: int = Field(..., gt=0)
    user_id: int = Field(..., gt=0)


class UserGroupPost(Base):
    user_id: int = Field(..., gt=0)


class GroupUserListGet(Base):
    items: list[UserInfo]


class ScopeGet(Base):
    id: int
    name: Scope
    comment: str | None


class ScopePost(Base):
    name: Scope
    comment: str | None


class ScopePatch(Base):
    name: Scope | None
    comment: str | None


class Session(Base):
    token: constr(min_length=1)
    expires: datetime
    id: int
    user_id: int
    session_scopes: list[Scope]


class SessionPost(Base):
    scopes: list[Scope] | None
    expires: datetime | None

    @classmethod
    @validator("expires")
    def expires_validator(cls, exp):
        if exp < datetime.utcnow():
            raise ValueError()
        return exp


Group.update_forward_refs()
GroupGet.update_forward_refs()
UserScopes.update_forward_refs()
UserGet.update_forward_refs()
SessionScopes.update_forward_refs()
