from __future__ import annotations

import datetime
from typing import Iterator

import sqlalchemy.orm
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property

from auth_backend.models.base import Base


class AuthMethods:
    class Method:
        pass

    def __init__(self, user: User):
        for method in user.auth_methods:
            if hasattr(self, method.auth_method):
                setattr(getattr(self, method.auth_method), method.param, method.value)
            else:
                setattr(self, method.auth_method, AuthMethods.Method())
                setattr(getattr(self, method.auth_method), method.param, method.value)


class User(Base):

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[UserSession] = sqlalchemy.orm.relationship("UserSession", foreign_keys="UserSession.user_id")

    @hybrid_method
    def get_method_secrets(self, method_name: str) -> Iterator[AuthMethod]:
        for row in self.auth_methods:
            if row.auth_method == method_name:
                yield row

    @hybrid_property
    def methods(self) -> AuthMethods:
        return AuthMethods(self)


class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"))
    auth_method = sqlalchemy.Column(sqlalchemy.String)
    param = sqlalchemy.Column(sqlalchemy.String)
    value = sqlalchemy.Column(sqlalchemy.String)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="auth_methods")


class UserSession(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"))
    expires = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="sessions")

    @hybrid_property
    def expired(self):
        return self.expires <= datetime.datetime.utcnow()
