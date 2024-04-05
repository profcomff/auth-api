from datetime import UTC, datetime

from sqlalchemy import DateTime, Double, Integer, String
from sqlalchemy.orm import Mapped, Session, mapped_column

from .base import Base


class DynamicOption(Base):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    value_integer: Mapped[int] = mapped_column(Integer, nullable=True)
    value_double: Mapped[float] = mapped_column(Double, nullable=True)
    value_string: Mapped[str] = mapped_column(String, nullable=True)
    create_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(UTC))
    update_ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(UTC), onupdate=datetime.now(UTC))

    @property
    def value(self) -> str | float | int:
        return self.value_double or self.value_integer or self.value_string

    @value.setter
    def set_value(self, value: str | float | int):
        if isinstance(value, str):
            self.value_string = value
        elif isinstance(value, float):
            self.value_double = value
        elif isinstance(value, int):
            self.value_integer = value
        else:
            raise TypeError("Only str, float or int options allowed")

    @staticmethod
    def get(name, default=None, *, session: Session):
        return session.query(DynamicOption).filter(DynamicOption.name == name).one_or_none() or default
