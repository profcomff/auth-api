from __future__ import annotations

import datetime
from typing import Iterator

import sqlalchemy.orm
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property

from auth_backend.models.base import Base


class AuthMethods:
    class Method:
        pass

    methods: dict[str, AuthMethods.Method]

    def __init__(self, user: User):
        self.methods = {}
        for method in user.auth_methods:
            if method.auth_method in self.methods.keys():
                setattr(self.methods[method.auth_method], method.param, method.value)
            else:
                self.methods[method.auth_method] = AuthMethods.Method()

    def __getattribute__(self, item) -> AuthMethods.Method:
        if item in self.methods.keys():
            return self.methods[item]
        raise AttributeError()


class User(Base):

    def __init__(self):
        super().__init__()
        self.methods = AuthMethods(self)

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    methods: AuthMethods

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[UserSession] = sqlalchemy.orm.relationship("UserSession", foreign_keys="UserSession.user_id")

    @hybrid_method
    def get_method_secrets(self, method_name: str) -> Iterator[AuthMethod]:
        for row in self.auth_methods:
            if row.auth_method == method_name:
                yield row


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
