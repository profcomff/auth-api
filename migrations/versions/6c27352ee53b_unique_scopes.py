"""unique_scopes
Revision ID: 6c27352ee53b
Revises: 586cf0e784e5
Create Date: 2023-03-12 23:39:28.891033
"""
import sqlalchemy as sa
from alembic import op


revision = '6c27352ee53b'
down_revision = '586cf0e784e5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint(None, 'scope', ['name'])


def downgrade():
    op.drop_constraint(None, 'scope', type_='unique')
