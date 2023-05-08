"""user_session_ts

Revision ID: b60fb541c140
Revises: fa4691ad1054
Create Date: 2023-05-09 00:18:37.779862

"""
import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b60fb541c140'
down_revision = 'fa4691ad1054'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('auth_method', sa.Column('create_ts', sa.DateTime(), nullable=False))
    op.add_column('auth_method', sa.Column('update_ts', sa.DateTime(), nullable=False))
    op.add_column('group', sa.Column('update_ts', sa.DateTime(), nullable=False))
    op.add_column('user', sa.Column('create_ts', sa.DateTime(), nullable=False))
    op.add_column('user', sa.Column('update_ts', sa.DateTime(), nullable=False))
    op.add_column('user_session', sa.Column('session_name', sa.String(), nullable=True))
    op.add_column('user_session', sa.Column('last_activity', sa.DateTime(), nullable=False))
    op.add_column('user_session', sa.Column('create_ts', sa.DateTime(), nullable=False))
    op.add_column('user_session', sa.Column('update_ts', sa.DateTime(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user_session', 'update_ts')
    op.drop_column('user_session', 'create_ts')
    op.drop_column('user_session', 'last_activity')
    op.drop_column('user_session', 'session_name')
    op.drop_column('user', 'update_ts')
    op.drop_column('user', 'create_ts')
    op.drop_column('group', 'update_ts')
    op.drop_column('auth_method', 'update_ts')
    op.drop_column('auth_method', 'create_ts')
    # ### end Alembic commands ###
