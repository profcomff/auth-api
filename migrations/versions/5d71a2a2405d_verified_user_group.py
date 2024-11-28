"""verified user group

Revision ID: 5d71a2a2405d
Revises: 2d29fc132e89
Create Date: 2024-11-28 00:01:19.608684

"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = '5d71a2a2405d'
down_revision = '2d29fc132e89'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    users_group_id = conn.execute(
        sa.text('SELECT "value_integer" FROM "dynamic_option" WHERE name=\'users_group_id\'')
    ).scalar()

    query = 'INSERT INTO "group" (name, parent_id, create_ts, is_deleted, update_ts) VALUES (:name, :parent_id, CURRENT_TIMESTAMP, false, CURRENT_TIMESTAMP)'
    conn.execute(sa.text(query).bindparams(name="verified", parent_id=users_group_id))

    verified_group_id = conn.execute(sa.text('SELECT "id" FROM "group" WHERE name=\'verified\'')).scalar()
    query = 'INSERT INTO "dynamic_option" (name, value_integer, create_ts, update_ts) VALUES (:name, :value_integer, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
    conn.execute(sa.text(query).bindparams(name="verified_group_id", value_integer=verified_group_id))

    verified_user_ids = conn.execute(
        sa.text('SELECT "user_id" FROM "auth_method" WHERE auth_method=\'lkmsu_auth\' AND is_deleted=\'false\'')
    ).scalars()
    query = 'INSERT INTO "user_group" VALUES (:user_id, :group_id, false)'
    for user_id in verified_user_ids:
        conn.execute(sa.text(query).bindparams(user_id=user_id, group_id=verified_group_id))


def downgrade():
    conn = op.get_bind()
    try:
        verified_group_id, option_id = conn.execute(
            sa.text('SELECT "value_integer", "id" FROM "dynamic_option" WHERE "name" = \'verified_group_id\'')
        ).one()
        conn.execute(
            sa.text('DELETE FROM "user_group" WHERE "group_id" = :group_id').bindparams(group_id=verified_group_id)
        )
        conn.execute(sa.text('DELETE FROM "group" WHERE "id" = :id').bindparams(id=verified_group_id))
        conn.execute(sa.text('DELETE FROM "dynamic_option" WHERE "id" = :id').bindparams(id=option_id))
    except Exception as e:
        pass
