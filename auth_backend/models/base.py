from __future__ import annotations

from contextlib import contextmanager
import re
import sys
from typing import Iterator

from sqlalchemy import Integer, not_
import sqlalchemy
from sqlalchemy.exc import NoResultFound
from sqlalchemy.orm import Mapped, Query, Session, as_declarative, declared_attr, mapped_column

from auth_backend.exceptions import ObjectNotFound


@as_declarative()
class Base:
    """Base class for all database entities"""

    @declared_attr
    def __tablename__(cls) -> str:  # pylint: disable=no-self-argument
        """Generate database table name automatically.
        Convert CamelCase class name to snake_case db table name.
        """
        return re.sub(r"(?<!^)(?=[A-Z])", "_", cls.__name__).lower()

    def __repr__(self):
        attrs = []
        for c in self.__table__.columns:
            attrs.append(f"{c.name}={getattr(self, c.name)}")
        return "{}({})".format(c.__class__.__name__, ', '.join(attrs))


class BaseDbModel(Base):
    __abstract__ = True
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    @classmethod
    def create(cls, *, session: Session, **kwargs) -> BaseDbModel:
        obj = cls(**kwargs)
        session.add(obj)
        session.flush()
        return obj

    @classmethod
    def query(cls, *, with_deleted: bool = False, session: Session) -> Query:
        """Get all objects with soft deletes"""
        objs = session.query(cls)
        if not with_deleted and hasattr(cls, "is_deleted"):
            objs = objs.filter(not_(cls.is_deleted))
        return objs

    @classmethod
    def get(cls, id: int, *, with_deleted=False, session: Session) -> BaseDbModel:
        """Get object with soft deletes"""
        objs = session.query(cls)
        if not with_deleted and hasattr(cls, "is_deleted"):
            objs = objs.filter(not_(cls.is_deleted))
        try:
            return objs.filter(cls.id == id).one()
        except NoResultFound:
            raise ObjectNotFound(cls, id)

    @classmethod
    def update(cls, id: int, *, session: Session, **kwargs) -> BaseDbModel:
        obj = cls.get(id, session=session)
        for k, v in kwargs.items():
            setattr(obj, k, v)
        session.flush()
        return obj

    @classmethod
    def delete(cls, id: int, *, session: Session) -> None:
        """Soft delete object if possible, else hard delete"""
        obj = cls.get(id, session=session)
        if hasattr(obj, "is_deleted"):
            obj.is_deleted = True
        else:
            session.delete(obj)
        session.flush()
    
    @classmethod
    @contextmanager
    def txn(cls, session: Session) -> Iterator[Session]:
        try:
            nested = session.begin_nested()
            session.execute(sqlalchemy.text(f'LOCK TABLE {cls.__tablename__} IN ACCESS EXCLUSIVE MODE;'))
            try:
                yield session
            except Exception:
                exception_name, _, __ = sys.exc_info()
                nested.rollback()
                session.rollback()
                if session and session.is_active:
                    session.close()
                raise
            finally:
                if locals().get("exception_name") is not None:
                    return
                nested.commit()
                session.commit()
                if session and session.is_active:
                    session.close()
        except Exception:
            raise
        
