import datetime

from auth_backend.base import Base


class UserInfo(Base):
    id: int
    email: str | None


class UserInfoWithGroups(UserInfo):
    groups: list[int]


class GroupGet(Base):
    id: int
    name: str
    parent_id: int | None
    create_ts: datetime.datetime


class GroupPost(Base):
    name: str
    parent_id: int | None


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None
    parent_id: int | None


class UserGroupGet(Base):
    group_id: int
    user_id: int


class UserGroupPost(Base):
    user_id: int


class GroupUserListGet(Base):
    items: list[UserInfo]
