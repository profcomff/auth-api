from alembic import op
import sqlalchemy as sa


revision = '6c27352ee53b'
down_revision = '586cf0e784e5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint(None, 'scope', ['name'])


def downgrade():
    op.drop_constraint(None, 'scope', type_='unique')
