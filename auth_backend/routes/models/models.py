from auth_backend.base import Base


class UserInfo(Base):
    id: int
    email: str | None
