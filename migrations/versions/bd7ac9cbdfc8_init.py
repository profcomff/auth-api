import sqlalchemy as sa
from alembic import op


revision = 'bd7ac9cbdfc8'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user', sa.Column('id', sa.Integer(), nullable=False), sa.PrimaryKeyConstraint('id'))
    op.create_table(
        'auth_method',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('auth_method', sa.String(), nullable=True),
        sa.Column('param', sa.String(), nullable=True),
        sa.Column('value', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ['user_id'],
            ['user.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'user_session',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('expires', sa.DateTime(), nullable=True),
        sa.Column('token', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ['user_id'],
            ['user.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )
    op.create_table(
        'user_message_delay',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_ip', sa.String(), nullable=True),
        sa.Column('user_email', sa.String(), nullable=True),
        sa.Column('delay_time', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade():
    op.drop_table('user_session')
    op.drop_table('auth_method')
    op.drop_table('user')
    op.drop_table('user_message_table')
