"""empty message

Revision ID: 2d9d8f4b00c5
Revises: None
Create Date: 2015-11-04 00:10:03.265496

"""

# revision identifiers, used by Alembic.
revision = '2d9d8f4b00c5'
down_revision = None

from alembic import op
import sqlalchemy as sa
import sqlalchemy_utils


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('org',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('orgs_parents',
    sa.Column('org_id', sa.Integer(), nullable=True),
    sa.Column('org_parent_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['org.id'], ),
    sa.ForeignKeyConstraint(['org_parent_id'], ['org.id'], )
    )
    op.create_table('portfolio',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('org_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['org.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('roles_parents',
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['parent_id'], ['role.id'], ),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], )
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('hash_id', sa.String(length=64), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('password', sa.String(length=80), nullable=False),
    sa.Column('org_id', sa.Integer(), nullable=True),
    sa.Column('secure_id', sa.String(length=80), nullable=True),
    sa.Column('first_name', sa.String(length=80), nullable=True),
    sa.Column('last_name', sa.String(length=80), nullable=True),
    sa.Column('user_guid', sqlalchemy_utils.types.uuid.UUIDType(binary=False), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['org.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('hash_id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('api__key',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('api_key', sa.String(length=64), nullable=False),
    sa.Column('secret_key', sa.String(length=128), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('api_key')
    )
    op.create_table('pub__key',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('pub_key', sa.String(length=128), nullable=False),
    sa.Column('priv_key', sa.String(length=128), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('priv_key'),
    sa.UniqueConstraint('pub_key')
    )
    op.create_table('users_roles',
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('parent_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['parent_id'], ['role.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users_roles')
    op.drop_table('pub__key')
    op.drop_table('api__key')
    op.drop_table('user')
    op.drop_table('roles_parents')
    op.drop_table('portfolio')
    op.drop_table('orgs_parents')
    op.drop_table('role')
    op.drop_table('org')
    ### end Alembic commands ###
