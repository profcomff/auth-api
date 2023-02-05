import datetime

from pydantic import Field

from auth_backend.base import Base


class UserInfo(Base):
    id: int
    email: str | None


class UserInfoWithGroups(UserInfo):
    groups: list[int]


class GroupGet(Base):
    id: int = Field(..., gt=0)
    name: str
    parent_id: int | None = Field(None, gt=0)
    create_ts: datetime.datetime


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
