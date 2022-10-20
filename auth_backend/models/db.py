from __future__ import annotations

import datetime

from .base import Base
import sqlalchemy.orm


class User(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[UserSession] = sqlalchemy.orm.relationship("UserSession", foreign_keys="UserSession.user_id")


class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    auth_method = sqlalchemy.Column(sqlalchemy.String)
    param = sqlalchemy.Column(sqlalchemy.String)
    value = sqlalchemy.Column(sqlalchemy.String)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="auth_methods")


class UserSession(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    expires = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="sessions")
