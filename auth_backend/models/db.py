from __future__ import annotations
import datetime
from typing import Iterator

from sqlalchemy.ext.hybrid import hybrid_method

from .base import Base
import sqlalchemy.orm


class User(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys=[id])
    sessions: list[Session] = sqlalchemy.orm.relationship("Session", foreign_keys=[id])

    @hybrid_method
    def get_auth_methods(self, auth_method: str) -> Iterator[AuthMethod]:
        for row in self.auth_methods:
            if row.auth_method == auth_method:
                yield row


class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    auth_method = sqlalchemy.Column(sqlalchemy.String)
    param = sqlalchemy.Column(sqlalchemy.String)
    value = sqlalchemy.Column(sqlalchemy.JSON)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="auth_methods")


class Session(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    expires = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="sessions")

    @property
    def expired(self):
        if self.expires <= datetime.datetime.utcnow():
            return True
        return False
