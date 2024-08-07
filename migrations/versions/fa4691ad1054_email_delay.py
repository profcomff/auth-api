"""email_delay

Revision ID: fa4691ad1054
Revises: c03c6b509881
Create Date: 2023-04-27 01:41:19.045346

"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = 'fa4691ad1054'
down_revision = 'c03c6b509881'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'user_message_delay',
        sa.Column('delay_time', sa.DateTime(), nullable=False),
        sa.Column('user_email', sa.String(), nullable=False),
        sa.Column('user_ip', sa.String(), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_message_delay')
    # ### end Alembic commands ###
