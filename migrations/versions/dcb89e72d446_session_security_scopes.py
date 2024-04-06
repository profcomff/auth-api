"""session_security_scopes

Revision ID: dcb89e72d446
Revises: 7c1cd7ceacd8
Create Date: 2024-04-06 02:06:15.967235

"""

from alembic import op
from sqlalchemy.orm import Session

from auth_backend.models.db import DynamicOption, Group, Scope, User, UserSession


# revision identifiers, used by Alembic.
revision = 'dcb89e72d446'
down_revision = '7c1cd7ceacd8'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    session = Session(conn)

    root_group_id: DynamicOption = session.query(DynamicOption).filter(DynamicOption.name == "root_group_id").one()
    users_group_id: DynamicOption = session.query(DynamicOption).filter(DynamicOption.name == "users_group_id").one()

    root_group: Group = Group.get(root_group_id.value_integer, session=session)
    user_group: Group = Group.get(users_group_id.value_integer, session=session)
    try:
        user = root_group.users[0]
    except IndexError:
        user = User.create(session=session)
        user.groups.append(root_group)

    scope1 = Scope(creator_id=user.id, name="auth.session.create", comment="Create user session")
    scope2 = Scope(creator_id=user.id, name="auth.session.update", comment="Update user session")
    session.add_all((scope1, scope2))
    session.flush()
    root_group.scopes.update([scope1, scope2])
    user_group.scopes.update([scope1, scope2])
    session.flush()
    user_sessions = UserSession.query(session=session).all()
    for user_session in user_sessions:
        user_session.scopes.extend((scope1, scope2))
    session.flush()
    session.commit()


def downgrade():
    pass
