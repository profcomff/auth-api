from sqlalchemy.orm import Session

from auth_backend.models.db import Scope


def create_scope(name: str, creator_id: int, comment: str, session: Session) -> None:
    scope = Scope(name=name, creator_id=creator_id, comment=comment)
    session.add(scope)
    session.commit()
