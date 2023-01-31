import datetime

from auth_backend.base import Base


class UserInfo(Base):
    id: int
    email: str | None


class GroupGet(Base):
    id: int
    name: str
    parent_id: int
    created_at: datetime.datetime


class GroupPost(Base):
    name: str
    parent_id: int


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None
    parent_id: int | None


class UserGroupGet(Base):
    group_id: int
    user_id: int


class GroupUserListGet(Base):
    items: list[UserInfo]