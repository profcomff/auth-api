"""session_security_scopes

Revision ID: dcb89e72d446
Revises: 7c1cd7ceacd8
Create Date: 2024-04-06 02:06:15.967235

"""

from alembic import op
from sqlalchemy.orm import Session

from auth_backend.models.db import DynamicOption, Group, Scope, User, UserSession, UserSessionScope


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
    sessions_id = session.query(UserSession.id).all()
    for session_id in sessions_id:
            UserSessionScope.create(user_session_id=session_id.id, scope_id=scope1.id, is_deleted=False, session=session)
            UserSessionScope.create(user_session_id=session_id.id, scope_id=scope2.id, is_deleted=False, session=session)
    session.commit()


def downgrade():
    pass
