from __future__ import annotations

import datetime
from typing import Iterator

import sqlalchemy.orm
from sqlalchemy.ext.hybrid import hybrid_method, hybrid_property

from auth_backend.models.base import Base


class User(Base):

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[UserSession] = sqlalchemy.orm.relationship("UserSession", foreign_keys="UserSession.user_id")

    # Type hints
    email: AuthMethod
    hashed_password: AuthMethod
    salt: AuthMethod
    tmp_email: AuthMethod
    confirmation_token: AuthMethod
    tmp_email_confirmation_token: AuthMethod
    reset_token: AuthMethod
    confirmed: AuthMethod

    def __init__(self):
        super(User, self).__init__()

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
