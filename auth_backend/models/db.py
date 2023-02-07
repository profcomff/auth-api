from __future__ import annotations

import datetime
from typing import Iterator

import sqlalchemy.orm
from sqlalchemy import String, Integer, ForeignKey, DateTime, Boolean
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column, relationship, backref

from auth_backend.models.base import BaseDbModel


class ParamDict:
    # Type hints
    email: AuthMethod
    hashed_password: AuthMethod
    salt: AuthMethod
    confirmed: AuthMethod
    confirmation_token: AuthMethod
    tmp_email: AuthMethod
    reset_token: AuthMethod
    tmp_email_confirmation_token: AuthMethod

    def __new__(cls, methods: list[AuthMethod], *args, **kwargs):
        obj = super(ParamDict, cls).__new__(cls)
        for row in methods:
            if attr := getattr(obj, row.param, None):
                if not isinstance(attr, AuthMethod):
                    raise AttributeError
            setattr(obj, row.param, row)
        return obj


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
    def active_sessions(self) -> list:
        return [row for row in self.sessions if not row.expired]

    @hybrid_property
    def auth_methods(self) -> ParamDict:
        """
        Эта функция возвращает экземпляр класса ParamDict, который создает внутри себя поля, соотвествуюшие:
        user.auth_methods.<param> = Соответствущему объекту AuthMethod
        :return: ParamDict
        """
        return ParamDict.__new__(ParamDict, self._auth_methods)


class Group(BaseDbModel):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    parent_id: Mapped[int] = mapped_column(Integer, ForeignKey("group.id"), nullable=True)
    create_ts: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    child: Mapped[list[Group]] = relationship(
        "Group",
        backref=backref("parent", remote_side=[id]),
        primaryjoin="and_(Group.id==Group.parent_id, not_(Group.is_deleted))",
    )
    users: Mapped[list[User]] = relationship(
        "User",
        secondary="user_group",
        back_populates="groups",
        primaryjoin="and_(Group.id==UserGroup.group_id, not_(UserGroup.is_deleted))",
        secondaryjoin="and_(User.id==UserGroup.user_id, not_(User.is_deleted))",
    )

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
    value: Mapped[str] = mapped_column(String)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="_auth_methods",
        primaryjoin="and_(AuthMethod.user_id==User.id, not_(User.is_deleted))",
    )


class UserSession(BaseDbModel):
    user_id: Mapped[int] = mapped_column(Integer, sqlalchemy.ForeignKey("user.id"))
    expires: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7)
    )
    token: Mapped[str] = mapped_column(String, unique=True)

    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="sessions",
        primaryjoin="and_(UserSession.user_id==User.id, not_(User.is_deleted))",
    )

    @hybrid_property
    def expired(self) -> bool:
        return self.expires <= datetime.datetime.utcnow()
