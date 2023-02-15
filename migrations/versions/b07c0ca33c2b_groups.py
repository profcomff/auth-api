"""groups

Revision ID: b07c0ca33c2b
Revises: bd7ac9cbdfc8
Create Date: 2023-01-30 00:34:42.158758

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'b07c0ca33c2b'
down_revision = 'bd7ac9cbdfc8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'group',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('parent_id', sa.Integer(), nullable=True),
        sa.Column('create_ts', sa.DateTime(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ['parent_id'],
            ['group.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_table(
        'user_group',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['group_id'],
            ['group.id'],
        ),
        sa.ForeignKeyConstraint(
            ['user_id'],
            ['user.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.add_column('auth_method', sa.Column('is_deleted', sa.Boolean()))
    op.execute('UPDATE "auth_method" SET is_deleted=false;')
    op.alter_column('auth_method', 'is_deleted', nullable=False)
    op.alter_column('auth_method', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.alter_column('auth_method', 'auth_method', existing_type=sa.VARCHAR(), nullable=False)
    op.alter_column('auth_method', 'param', existing_type=sa.VARCHAR(), nullable=False)
    op.alter_column('auth_method', 'value', existing_type=sa.VARCHAR(), nullable=True)
    op.add_column('user', sa.Column('is_deleted', sa.Boolean()))
    op.execute('UPDATE "user" SET is_deleted=false;')
    op.alter_column('user', 'is_deleted', nullable=False)
    op.alter_column('user_session', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.alter_column('user_session', 'expires', existing_type=postgresql.TIMESTAMP(), nullable=False)
    op.alter_column('user_session', 'token', existing_type=sa.VARCHAR(), nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('user_session', 'token', existing_type=sa.VARCHAR(), nullable=True)
    op.alter_column('user_session', 'expires', existing_type=postgresql.TIMESTAMP(), nullable=True)
    op.alter_column('user_session', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.drop_column('user', 'is_deleted')
    op.alter_column('auth_method', 'value', existing_type=sa.VARCHAR(), nullable=True)
    op.alter_column('auth_method', 'param', existing_type=sa.VARCHAR(), nullable=True)
    op.alter_column('auth_method', 'auth_method', existing_type=sa.VARCHAR(), nullable=True)
    op.alter_column('auth_method', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.drop_column('auth_method', 'is_deleted')
    op.drop_table('user_group')
    op.drop_table('group')
    # ### end Alembic commands ###