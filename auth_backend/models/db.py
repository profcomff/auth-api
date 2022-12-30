from __future__ import annotations

import datetime

import sqlalchemy.orm
from sqlalchemy.ext.hybrid import hybrid_property

from auth_backend.models.base import Base


class ParamDict:
    def __new__(cls, methods: list[AuthMethod], *args, **kwargs):
        obj = super(ParamDict, cls).__new__(cls)
        for row in methods:
            if attr := getattr(obj, row.param, None):
                if not isinstance(attr, AuthMethod):
                    raise AttributeError
            setattr(obj, row.param, row)
        return obj


class User(Base):

    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)

    _auth_methods: list[AuthMethod] = sqlalchemy.orm.relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: list[UserSession] = sqlalchemy.orm.relationship("UserSession", foreign_keys="UserSession.user_id")

    @hybrid_property
    def auth_methods(self) -> ParamDict:
        """
        Эта функция возвращает экземпляр класса ParamDict, который создает внутри себя поля, соотвествуюшие:
        user.auth_methods.<param> = Соответствущему объекту AuthMethod
        :return: ParamDict
        """
        return ParamDict.__new__(ParamDict, self._auth_methods)


class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"))
    auth_method = sqlalchemy.Column(sqlalchemy.String)
    param = sqlalchemy.Column(sqlalchemy.String)
    value = sqlalchemy.Column(sqlalchemy.String)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="_auth_methods")


class UserSession(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("user.id"))
    expires = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)

    user: User = sqlalchemy.orm.relationship("User", foreign_keys=[user_id], back_populates="sessions")

    @hybrid_property
    def expired(self):
        return self.expires <= datetime.datetime.utcnow()
