import datetime

from .base import Base
import sqlalchemy.orm


class User(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)



class AuthMethod(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    auth_method = sqlalchemy.Column(sqlalchemy.String)
    param = sqlalchemy.Column(sqlalchemy.String)
    value = sqlalchemy.Column(sqlalchemy.String)


class Session(Base):
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("User.id"))
    expires = sqlalchemy.Column(sqlalchemy.DateTime, default=datetime.datetime.utcnow() + datetime.timedelta(days=7))
    token = sqlalchemy.Column(sqlalchemy.String, unique=True)
