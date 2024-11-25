"""193 Add unbounded sessions

Revision ID: 6dffd8e42152
Revises: 2d29fc132e89
Create Date: 2024-08-19 19:27:25.867548

"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = '6dffd8e42152'
down_revision = '2d29fc132e89'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user_session', sa.Column('is_unbounded', sa.Boolean(), nullable=True))
    op.execute("UPDATE user_session SET is_unbounded='false'")
    op.alter_column('user_session', 'is_unbounded', nullable=False)


def downgrade():
    op.drop_column('user_session', 'is_unbounded')
