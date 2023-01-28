from __future__ import annotations

import datetime

import sqlalchemy.orm
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import String, Integer, ForeignKey, DateTime
from sqlalchemy.ext.hybrid import hybrid_property

from auth_backend.models.base import Base


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


class User(Base):

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    _auth_methods: Mapped[list["AuthMethod"]] = relationship("AuthMethod", foreign_keys="AuthMethod.user_id")
    sessions: Mapped[list["UserSession"]] = relationship("UserSession", foreign_keys="UserSession.user_id")

    @hybrid_property
    def auth_methods(self) -> ParamDict:
        """
        Эта функция возвращает экземпляр класса ParamDict, который создает внутри себя поля, соотвествуюшие:
        user.auth_methods.<param> = Соответствущему объекту AuthMethod
        :return: ParamDict
        """
        return ParamDict.__new__(ParamDict, self._auth_methods)


class AuthMethod(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("user.id"))
    auth_method: Mapped[str] = mapped_column(String)
    param: Mapped[str] = mapped_column(String)
    value: Mapped[str] = mapped_column(String)

    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="_auth_methods")


class UserSession(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, sqlalchemy.ForeignKey("user.id"))
    expires: Mapped[datetime.datetime] = mapped_column(DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token: Mapped[str] = mapped_column(String, unique=True)

    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="sessions")

    @hybrid_property
    def expired(self):
        return self.expires <= datetime.datetime.utcnow()
