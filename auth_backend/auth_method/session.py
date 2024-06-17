from datetime import datetime
from typing import Annotated

from annotated_types import MinLen

from auth_backend.base import Base
from auth_backend.schemas.types.scopes import Scope as TypeScope


class Session(Base):
    token: Annotated[str, MinLen(1)]
    expires: datetime
    id: int
    user_id: int
    session_scopes: list[TypeScope]
