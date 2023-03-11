from sqlalchemy.orm import Session

from auth_backend.models.db import UserGroup


def create_user_group(user_id: int, group_id: int, session: Session) -> None:
    session.add(UserGroup(user_id=user_id, group_id=group_id))
    session.commit()
