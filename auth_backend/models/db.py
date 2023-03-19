from __future__ import annotations

import datetime
from typing import Iterator

import sqlalchemy.orm
from sqlalchemy import String, Integer, ForeignKey, DateTime, Boolean, func
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column, relationship, backref, Session

from auth_backend.exceptions import ObjectNotFound
from auth_backend.settings import get_settings

settings = get_settings()


from auth_backend.models.base import BaseDbModel


class User(BaseDbModel):
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    _auth_methods: Mapped[list[AuthMethod]] = relationship(
        "AuthMethod",
        foreign_keys="AuthMethod.user_id",
        primaryjoin="and_(User.id==AuthMethod.user_id, not_(AuthMethod.is_deleted))",
    )
    sessions: Mapped[list[UserSession]] = relationship(
        "UserSession", foreign_keys="UserSession.user_id", back_populates="user"
    )
    groups: Mapped[list[Group]] = relationship(
        "Group",
        secondary="user_group",
        back_populates="users",
        primaryjoin="and_(User.id==UserGroup.user_id, not_(UserGroup.is_deleted))",
        secondaryjoin="and_(Group.id==UserGroup.group_id, not_(Group.is_deleted))",
    )

    @hybrid_property
    def scopes(self) -> set[Scope]:
        _scopes = set()
        for group in self.groups:
            _scopes.update(group.indirect_scopes)
        return _scopes

    @hybrid_property
    def indirect_groups(self) -> set[Group]:
        _groups = set()
        _groups.update(set(self.groups))
        for group in self.groups:
            _groups.update(group.parents)
        return _groups

    @hybrid_property
    def active_sessions(self) -> list[UserSession]:
        return [row for row in self.sessions if not row.expired]

    @hybrid_property
    def auth_methods(self):
        """
        Эта функция возвращает экземпляр класса MethodsDict, который создает внутри себя поля, соотвествуюшие:
        user.auth_methods.<param> = Соответствущему объекту MethodsMeta
        Пример: user.auth_methods.email.email.value
        :return: MethodsDict
        """
        from auth_backend.auth_plugins.db_plugins import MethodsDict

        return MethodsDict.__new__(MethodsDict, self._auth_methods)


class Group(BaseDbModel):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=False, nullable=False)
    parent_id: Mapped[int] = mapped_column(Integer, ForeignKey("group.id"), nullable=True)
    create_ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    child: Mapped[list[Group]] = relationship(
        "Group",
        backref=backref("parent", remote_side=[id]),
        primaryjoin="and_(remote(Group.parent_id)==Group.id, not_(remote(Group.is_deleted)))",
    )

    users: Mapped[list[User]] = relationship(
        "User",
        secondary="user_group",
        back_populates="groups",
        primaryjoin="and_(Group.id==UserGroup.group_id, not_(UserGroup.is_deleted))",
        secondaryjoin="and_(User.id==UserGroup.user_id, not_(User.is_deleted))",
    )

    scopes: Mapped[set[Scope]] = relationship(
        "Scope",
        back_populates="groups",
        secondary="group_scope",
        primaryjoin="and_(Group.id==GroupScope.group_id, not_(GroupScope.is_deleted))",
        secondaryjoin="and_(Scope.id==GroupScope.scope_id, not_(Scope.is_deleted))",
    )

    @hybrid_property
    def indirect_scopes(self) -> set[Scope]:
        _indirect_scopes = set()
        _indirect_scopes.update(self.scopes)
        for group in self.parents:
            _indirect_scopes.update(group.scopes)
        return _indirect_scopes

    @hybrid_property
    def parents(self) -> Iterator[Group]:
        parent = self
        while parent := parent.parent:
            yield parent


class UserGroup(BaseDbModel):
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"))
    group_id: Mapped[int] = mapped_column(Integer, ForeignKey("group.id"))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)


class AuthMethod(BaseDbModel):
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"))
    auth_method: Mapped[str] = mapped_column(String)
    param: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(String, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="_auth_methods",
        primaryjoin="and_(AuthMethod.user_id==User.id, not_(User.is_deleted))",
    )


def session_expires_date():
    return datetime.datetime.utcnow() + datetime.timedelta(days=settings.SESSION_TIME_IN_DAYS)


class UserSession(BaseDbModel):
    user_id: Mapped[int] = mapped_column(Integer, sqlalchemy.ForeignKey("user.id"))
    expires: Mapped[datetime.datetime] = mapped_column(DateTime, default=session_expires_date)
    token: Mapped[str] = mapped_column(String, unique=True)

    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="sessions",
        primaryjoin="and_(UserSession.user_id==User.id, not_(User.is_deleted))",
    )
    scopes: Mapped[list[Scope]] = relationship(
        "Scope",
        back_populates="user_sessions",
        secondary="user_session_scope",
        primaryjoin="and_(UserSession.id==UserSessionScope.user_session_id, not_(UserSessionScope.is_deleted))",
        secondaryjoin="and_(Scope.id==UserSessionScope.scope_id, not_(Scope.is_deleted))",
    )

    @hybrid_property
    def expired(self) -> bool:
        return self.expires <= datetime.datetime.utcnow()


class Scope(BaseDbModel):
    creator_id: Mapped[int] = mapped_column(Integer, ForeignKey(User.id))
    name: Mapped[str] = mapped_column(String, unique=False)
    comment: Mapped[str] = mapped_column(String, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    groups: Mapped[list[Group]] = relationship(
        Group,
        back_populates="scopes",
        secondary="group_scope",
        primaryjoin="and_(Scope.id==GroupScope.scope_id, not_(GroupScope.is_deleted))",
        secondaryjoin="and_(Group.id==GroupScope.group_id, not_(Group.is_deleted))",
    )
    user_sessions: Mapped[list[UserSession]] = relationship(
        UserSession,
        back_populates="scopes",
        secondary="user_session_scope",
        primaryjoin="and_(Scope.id==UserSessionScope.scope_id, not_(UserSessionScope.is_deleted))",
        secondaryjoin="(UserSession.id==UserSessionScope.user_session_id)",
    )

    @classmethod
    def get_by_name(cls, name: str, *, with_deleted: bool = False, session: Session) -> Scope:
        scope = (
            cls.query(with_deleted=with_deleted, session=session)
            .filter(func.lower(cls.name) == name.lower())
            .one_or_none()
        )
        if not scope:
            raise ObjectNotFound(cls, name)
        return scope


class GroupScope(BaseDbModel):
    group_id: Mapped[int] = mapped_column(Integer, ForeignKey(Group.id))
    scope_id: Mapped[int] = mapped_column(Integer, ForeignKey(Scope.id))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)


class UserSessionScope(BaseDbModel):
    user_session_id: Mapped[int] = mapped_column(Integer, ForeignKey(UserSession.id))
    scope_id: Mapped[int] = mapped_column(Integer, ForeignKey(Scope.id))
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
