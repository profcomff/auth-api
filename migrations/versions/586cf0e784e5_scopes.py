"""scopes

Revision ID: 586cf0e784e5
Revises: b07c0ca33c2b
Create Date: 2023-02-22 20:16:06.859484

"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = '586cf0e784e5'
down_revision = 'b07c0ca33c2b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'scope',
        sa.Column('creator_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('comment', sa.String(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['creator_id'],
            ['user.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'group_scope',
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('scope_id', sa.Integer(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['group_id'],
            ['group.id'],
        ),
        sa.ForeignKeyConstraint(
            ['scope_id'],
            ['scope.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'user_session_scope',
        sa.Column('user_session_id', sa.Integer(), nullable=False),
        sa.Column('scope_id', sa.Integer(), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['scope_id'],
            ['scope.id'],
        ),
        sa.ForeignKeyConstraint(
            ['user_session_id'],
            ['user_session.id'],
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.alter_column('auth_method', 'value', existing_type=sa.VARCHAR(), nullable=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('auth_method', 'value', existing_type=sa.VARCHAR(), nullable=True)
    op.drop_table('user_session_scope')
    op.drop_table('group_scope')
    op.drop_table('scope')
    # ### end Alembic commands ###
