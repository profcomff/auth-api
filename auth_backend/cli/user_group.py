import errno

from sqlalchemy.orm import Session

from auth_backend.models.db import AuthMethod, Group, UserGroup


def create_user_group(email: str, session: Session) -> None:
    user_id = AuthMethod.query(session=session).filter(AuthMethod.auth_method == "email", AuthMethod.value == email).one().user_id
    group_id = Group.query(session=session).filter(Group.name == "root").one().id
    if (
        UserGroup.query(session=session)
        .filter(UserGroup.user_id == user_id, UserGroup.group_id == group_id)
        .one_or_none()
    ):
        print("User already in group")
        exit(errno.EIO)
    session.add(user_group := UserGroup(user_id=user_id, group_id=group_id))
    session.commit()
    print(f"Created user_group: {user_group}")
