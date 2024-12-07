"""session_security_scopes

Revision ID: dcb89e72d446
Revises: 7c1cd7ceacd8
Create Date: 2024-04-06 02:06:15.967235

"""

from alembic import op
from sqlalchemy.sql import text


# revision identifiers, used by Alembic.
revision = 'dcb89e72d446'
down_revision = '7c1cd7ceacd8'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()

    query: str = 'SELECT value_integer FROM dynamic_option WHERE name=:option_name'
    root_group_id: int = conn.execute(text(query).bindparams(option_name="root_group_id")).scalar()
    users_group_id: int = conn.execute(text(query).bindparams(option_name="users_group_id")).scalar()

    query = 'SELECT user_id FROM user_group WHERE group_id=:group_id'
    root_user_id = conn.execute(text(query).bindparams(group_id=root_group_id)).scalar()
    if root_user_id is None:
        query = (
            'INSERT INTO "user" (is_deleted, create_ts, update_ts) VALUES (false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
        )
        conn.execute(text(query))

        query = 'INSERT INTO "user_group" VALUES (:user_id, :group_id, false)'
        root_user_id = conn.execute(text('SELECT id FROM "user" ORDER BY id DESC')).scalar()
        conn.execute(text(query).bindparams(user_id=root_user_id, group_id=root_group_id))

    query = 'INSERT INTO "scope" VALUES (:creator_id, :name, :comment, false)'
    conn.execute(
        text(query).bindparams(creator_id=root_user_id, name="auth.session.create", comment="Create user session")
    )
    conn.execute(
        text(query).bindparams(creator_id=root_user_id, name="auth.session.update", comment="Update user session")
    )

    query = 'SELECT id FROM scope WHERE name=:name'
    scope1_id = conn.execute(text(query).bindparams(name="auth.session.create")).scalar()
    scope2_id = conn.execute(text(query).bindparams(name="auth.session.update")).scalar()

    query = 'INSERT INTO "group_scope" VALUES (:group_id, :scope_id, false)'
    conn.execute(text(query).bindparams(group_id=root_group_id, scope_id=scope1_id))
    conn.execute(text(query).bindparams(group_id=root_group_id, scope_id=scope2_id))
    conn.execute(text(query).bindparams(group_id=users_group_id, scope_id=scope1_id))
    conn.execute(text(query).bindparams(group_id=users_group_id, scope_id=scope2_id))

    session_ids = conn.execute(text('SELECT id FROM user_session')).all()
    query = 'INSERT INTO "user_session_scope" VALUES (:user_session_id, :scope_id, false)'
    for session_id in session_ids:
        conn.execute(text(query).bindparams(user_session_id=session_id[0], scope_id=scope1_id))
        conn.execute(text(query).bindparams(user_session_id=session_id[0], scope_id=scope2_id))


def downgrade():
    pass
