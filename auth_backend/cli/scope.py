import errno

from sqlalchemy.orm import Session

from auth_backend.models.db import AuthMethod, Scope


def create_scope(name: str, creator_email: str, comment: str, session: Session) -> None:
    if Scope.query(session=session).filter(Scope.name == name).one_or_none():
        print("Scope already exists")
        exit(errno.EIO)
    creator_id = AuthMethod.query(session=session).filter(AuthMethod.auth_method == "email", AuthMethod.value == creator_email).one().user_id
    scope = Scope.create(name=name, creator_id=creator_id, comment=comment, session=session)
    session.commit()
    print(f"Created scope: {scope}")
