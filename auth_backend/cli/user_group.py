import errno

from sqlalchemy.orm import Session

from auth_backend.models.db import UserGroup


def create_user_group(user_id: int, group_id: int, session: Session) -> None:
    if UserGroup.query(session=session).filter(UserGroup.user_id == user_id, UserGroup.group_id == group_id).obe_or_none():
        print("User already in group")
        exit(errno.EIO)
    session.add(user_group := UserGroup(user_id=user_id, group_id=group_id))
    session.commit()
    print(f"Created user_group: {user_group}")
