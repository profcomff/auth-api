"""Dynamic option model

Revision ID: 7c1cd7ceacd8
Revises: bda218c91211
Create Date: 2024-04-05 22:36:58.224670

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session
from auth_backend.models.db import Group


# revision identifiers, used by Alembic.
revision = '7c1cd7ceacd8'
down_revision = 'bda218c91211'
branch_labels = None
depends_on = None


def upgrade():
    dynamic_option_table = op.create_table(
        'dynamic_option',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False, unique=True),
        sa.Column('value_integer', sa.Integer(), nullable=True),
        sa.Column('value_double', sa.Double(), nullable=True),
        sa.Column('value_string', sa.String(), nullable=True),
        sa.Column('create_ts', sa.DateTime(), nullable=False),
        sa.Column('update_ts', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )

    conn = op.get_bind()
    session = Session(conn)
    try:
        root_group_id = session.execute(sa.text("SELECT \"id\" FROM \"group\" WHERE name = 'root'")).scalar()
    except Exception:
        pass

    if root_group_id is None:
        group: Group = Group.create(name="root", session=session)
        for scope in session.execute(sa.text("SELECT * FROM \"scope\"")):
            group.scopes.add(scope["id"])
        root_group_id = group.id

    try:
        users_group_id = session.execute(sa.text("SELECT \"id\" FROM \"group\" WHERE name = 'users'")).scalar()
    except Exception:
        pass

    if users_group_id is None:
        group: Group = Group.create(name="users", session=session)
        for user in session.execute(sa.text("SELECT * FROM \"user\"")):
            group.users.append(user["id"])
        users_group_id = group.id

    session.flush()

    values = [
        {"name": "root_group_id", "create_ts": "now()", "update_ts": "now()", "value_integer": root_group_id},
        {"name": "users_group_id", "create_ts": "now()", "update_ts": "now()", "value_integer": users_group_id},
    ]
    op.bulk_insert(dynamic_option_table, values)


def downgrade():
    op.drop_table('dynamic_option')
