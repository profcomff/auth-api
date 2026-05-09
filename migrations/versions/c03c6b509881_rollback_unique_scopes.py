"""rollback_unique_scopes

Revision ID: c03c6b509881
Revises: 6c27352ee53b
Create Date: 2023-03-14 19:29:02.419553

"""

from alembic import op


revision = 'c03c6b509881'
down_revision = '6c27352ee53b'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('group_name_key', 'group', type_='unique')
    op.drop_constraint('scope_name_key', 'scope', type_='unique')


def downgrade():
    op.create_unique_constraint('scope_name_key', 'scope', ['name'])
    op.create_unique_constraint('group_name_key', 'group', ['name'])
