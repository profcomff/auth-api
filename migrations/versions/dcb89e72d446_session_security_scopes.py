"""session_security_scopes

Revision ID: dcb89e72d446
Revises: 7c1cd7ceacd8
Create Date: 2024-04-06 02:06:15.967235

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from auth_backend.models.db import Group, GroupScope, Scope, User, UserGroup, UserSession, UserSessionScope


# revision identifiers, used by Alembic.
revision = 'dcb89e72d446'
down_revision = '7c1cd7ceacd8'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    session = Session(conn)

    root_group: Group = Group.query(session=session).filter(Group.name == "root").one()
    user_group: Group = Group.query(session=session).filter(Group.name == "users").one()
    try:
        user = root_group.users[0]
    except KeyError:
        user = User.create(session=session)
        UserGroup.create(session=session, user_id=user.id, group_id=root_group.id)

    scope1 = Scope(creator_id=user.id, name="auth.session.create", comment="Create user session")
    scope2 = Scope(creator_id=user.id, name="auth.session.update", comment="Update user session")
    session.add_all((scope1, scope2))
    session.flush()
    root_group_scope1 = GroupScope(group_id=root_group.id, scope_id=scope1.id)
    root_group_scope2 = GroupScope(group_id=root_group.id, scope_id=scope2.id)
    user_group_scope1 = GroupScope(group_id=user_group.id, scope_id=scope1.id)
    user_group_scope2 = GroupScope(group_id=user_group.id, scope_id=scope1.id)
    session.add_all((root_group_scope1, root_group_scope2, user_group_scope1, user_group_scope2))
    session.flush()
    user_sessions = UserSession.query(session=session).all()
    for user_session in user_sessions:
        session.add(UserSessionScope(user_session_id=user_session.id, scope_id=scope1.id))
        session.add(UserSessionScope(user_session_id=user_session.id, scope_id=scope2.id))
    session.flush()
    session.commit()


def downgrade():
    conn = op.get_bind()
    session = Session(conn)

    scope1 = Scope.query(session=session).filter(Scope.name == "auth.session.create").one()
    scope2 = Scope.query(session=session).filter(Scope.name == "auth.session.update").one()

    UserSessionScope.query(session=session).filter(UserSessionScope.scope_id == scope1.id).delete()
    UserSessionScope.query(session=session).filter(UserSessionScope.scope_id == scope2.id).delete()

    GroupScope.query(session=session).filter(GroupScope.scope_id == scope1.id).delete()
    GroupScope.query(session=session).filter(GroupScope.scope_id == scope2.id).delete()

    session.delete(scope1)
    session.delete(scope2)

    session.flush()
    session.commit()
