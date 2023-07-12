from __future__ import annotations

from datetime import datetime

from pydantic import ConfigDict, Field, constr, field_validator

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
    # TODO[pydantic]: The following keys were removed: `fields`.
    # Check https://docs.pydantic.dev/dev-v2/migration/#changes-to-config for more information.
    model_config = ConfigDict(fields={'session_scopes': {'exclude': True}})


class UserPatch(Base):
    groups: list[int]


class GroupPost(Base):
    name: str
    parent_id: int | None = Field(None, gt=0)
    scopes: list[int]


class GroupsGet(Base):
    items: list[GroupGet]


class GroupPatch(Base):
    name: str | None = None
    parent_id: int | None = Field(None, gt=0)
    scopes: list[int] | None = None


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
    comment: str | None = None


class ScopePost(Base):
    name: Scope
    comment: str | None = None


class ScopePatch(Base):
    name: Scope | None = None
    comment: str | None = None


class Session(Base):
    session_name: str | None = None
    token: constr(min_length=1) | None = None
    expires: datetime | None = None
    id: int
    user_id: int
    session_scopes: list[Scope] | None = None
    last_activity: datetime


class SessionPost(Base):
    session_name: str | None = None
    scopes: list[Scope] = []
    expires: datetime | None = None

    @classmethod
    @field_validator("expires")
    @classmethod
    def expires_validator(cls, exp):
        if exp < datetime.utcnow():
            raise ValueError()
        return exp


Group.update_forward_refs()
GroupGet.update_forward_refs()
UserScopes.update_forward_refs()
UserGet.update_forward_refs()
SessionScopes.update_forward_refs()
