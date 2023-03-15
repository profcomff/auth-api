from __future__ import annotations

from pydantic import Field

from auth_backend.base import Base
from auth_backend.schemas.types.scopes import Scope


class Group(Base):
    id: int = Field(..., gt=0)
    name: str
    parent_id: int | None = Field(None, gt=0)


class GroupScopes(Base):
    scopes: list[int] | None


class GroupChilds(Base):
    child: list[Group] | None


class GroupIndirectScopes(Base):
    indirect_scopes: list[int] | None


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
    user_scopes: list[int] | None


class SessionScopes(Base):
    session_scopes: list[int] | None


class UserGet(UserInfo, UserGroups, UserIndirectGroups, UserScopes, SessionScopes):
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


Group.update_forward_refs()
GroupGet.update_forward_refs()
UserScopes.update_forward_refs()
UserGet.update_forward_refs()
SessionScopes.update_forward_refs()
