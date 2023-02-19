from __future__ import annotations

from pydantic import Field, validator

from auth_backend.base import Base


class Group(Base):
    id: int = Field(..., gt=0)
    name: str
    parent_id: int | None = Field(None, gt=0)
    scopes: list[ScopeGet]


class GroupChilds(Base):
    child: list[Group] | None


class GroupIndirectScopes(Base):
    indirect_scopes: list[ScopeGet] | None


class GroupGet(Group, GroupChilds, GroupIndirectScopes):
    pass


class UserInfo(Base):
    id: int
    email: str | None


class UserGroups(Base):
    groups: list[Group] | None


class UserIndirectGroups(Base):
    indirect_groups: list[Group] | None


class UserGet(UserInfo, UserGroups, UserIndirectGroups):
    pass


class GroupPost(Base):
    name: str
    parent_id: int | None = Field(None, gt=0)
    scopes: list[int]


class GroupsGet(Base):
    items: list[Group]


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


def scope_validator(v: str) -> str:
    if " " in v:
        raise ValueError
    if v.count(".") != 2:
        raise ValueError
    if not all(v.split(".")):
        raise ValueError
    return v


def patch_scope_validator(v: str) -> str:
    if not v:
        return v
    return scope_validator(v)


class ScopeGet(Base):
    id: int
    name: str
    comment: str | None

    validator_name = validator("name", allow_reuse=True)(scope_validator)


class ScopePost(Base):
    name: str
    comment: str | None

    validator_name = validator("name", allow_reuse=True)(scope_validator)


class ScopePatch(Base):
    name: str | None
    comment: str | None

    validator_name = validator("name", allow_reuse=True)(patch_scope_validator)


Group.update_forward_refs()
GroupGet.update_forward_refs()
