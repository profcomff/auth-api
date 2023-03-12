"""unique_scopes

Revision ID: 6c27352ee53b
Revises: 586cf0e784e5
Create Date: 2023-03-12 23:39:28.891033

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6c27352ee53b'
down_revision = '586cf0e784e5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_unique_constraint(None, 'scope', ['name'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'scope', type_='unique')
    # ### end Alembic commands ###
