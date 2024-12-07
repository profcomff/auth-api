"""merge unbounded and verified

Revision ID: ed1a7f2276d4
Revises: 5d71a2a2405d, 6dffd8e42152
Create Date: 2024-12-07 12:58:57.981808

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ed1a7f2276d4'
down_revision = ('5d71a2a2405d', '6dffd8e42152')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
