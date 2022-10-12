from __future__ import annotations
import datetime
from typing import Iterator

from sqlalchemy.ext.hybrid import hybrid_method


from .base import Base
import sqlalchemy.orm
from sqlalchemy.dialects.postgresql.json import JSON


class User(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[Session] = sqlalchemy.orm.relationship("Session", foreign_keys="Session.user_id")

    @hybrid_method
    def get_auth_methods(self, auth_method: str) -> Iterator[AuthMethod]:
        for row in self.auth_methods:
            if row.auth_method == auth_method:
                yield row


class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"), nullable=False)
    auth_method = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    param = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    value = sqlalchemy.Column(sqlalchemy.String, nullable=False)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="auth_methods")


class Session(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"), nullable=False)
    expires = sqlalchemy.Column(
        sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7), nullable=False
    )
    token = sqlalchemy.Column(sqlalchemy.String, unique=True, nullable=False)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="sessions")

    @property
    def expired(self):
        if self.expires <= datetime.datetime.utcnow():
            return True
        return False
