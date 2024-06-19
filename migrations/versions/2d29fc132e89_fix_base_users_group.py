"""Fix users group assignment

Revision ID: 2d29fc132e89
Revises: dcb89e72d446
Create Date: 2024-06-18 19:06:56.880543

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.orm import Session

from auth_backend.models.db import Group, User


# revision identifiers, used by Alembic.
revision = '2d29fc132e89'
down_revision = 'dcb89e72d446'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    session = Session(conn)

    users_group_id = session.execute(
        sa.text("SELECT \"value_integer\" FROM \"dynamic_option\" WHERE name = 'users_group_id'")
    ).scalar()
    group: Group = Group.get(users_group_id, session=session, with_deleted=True)

    users = session.execute(sa.text("SELECT id FROM \"user\"")).fetchall()
    for user_id in users:
        user = User.get(user_id[0], with_deleted=True, session=session)
        if user not in group.users:
            group.users.append(user)

    session.commit()


def downgrade():
    pass
