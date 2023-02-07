from __future__ import annotations
import datetime

from pydantic import Field

from auth_backend.base import Base


class GroupGet(Base):
    id: int = Field(..., gt=0)
    name: str
    parent_id: int | None = Field(None, gt=0)


class UserInfo(Base):
    id: int
    email: str | None


class UserGroups(Base):
    groups: list[GroupGet] | None


class UserIndirectGroups(Base):
    indirect_groups: list[GroupGet] | None


class UserGet(UserInfo, UserGroups, UserIndirectGroups):
    pass


class GroupGetWithChilds(GroupGet):
    childs: list[GroupGet]


class GroupPost(Base):
    name: str
    parent_id: int | None = Field(None, gt=0)


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None
    parent_id: int | None = Field(None, gt=0)


class UserGroupGet(Base):
    group_id: int = Field(..., gt=0)
    user_id: int = Field(..., gt=0)


class UserGroupPost(Base):
    user_id: int = Field(..., gt=0)


class GroupUserListGet(Base):
    items: list[UserInfo]
