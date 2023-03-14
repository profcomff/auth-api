from alembic import op
import sqlalchemy as sa


revision = '89f7a1a1c063'
down_revision = '6c27352ee53b'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('group_name_key', 'group', type_='unique')
    op.drop_constraint('scope_name_key', 'scope', type_='unique')


def downgrade():
    op.create_unique_constraint('scope_name_key', 'scope', ['name'])
    op.create_unique_constraint('group_name_key', 'group', ['name'])
