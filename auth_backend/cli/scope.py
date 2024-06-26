import errno

from sqlalchemy.orm import Session

from auth_backend.models.db import Scope


def create_scope(name: str, creator_id: int, comment: str, session: Session) -> None:
    if Scope.query(session=session).filter(Scope.name == name).one_or_none():
        print("Scope already exists")
        exit(errno.EIO)
    scope = Scope.create(name=name, creator_id=creator_id, comment=comment, session=session)
    session.commit()
    print(f"Created scope: {scope}")
