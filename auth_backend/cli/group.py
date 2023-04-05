import errno

from sqlalchemy.orm import Session

from auth_backend.models.db import Group, GroupScope


def create_group(name: str, scopes: str, parent_id: int, session: Session) -> None:
    if Group.query(session=session).filter(Group.name == name).one_or_none():
        print("Group already exists")
        exit(errno.EIO)
    group = Group.create(name=name, parent_id=parent_id, session=session)
    session.flush()
    for id in scopes:
        session.add(GroupScope(group_id=group.id, scope_id=id))
    session.commit()
    print(f"Created group: {group}, with scopes: {scopes}")
