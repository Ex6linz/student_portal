"""media table

Revision ID: a730f0e9380e
Revises: cad07fe7563f
Create Date: 2025-05-25 09:03:57.526137

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
import sqlmodel.sql.sqltypes
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a730f0e9380e'
down_revision: Union[str, None] = 'cad07fe7563f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('media',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('owner_id', sa.UUID(), nullable=False),
    sa.Column('filename', sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
    sa.Column('mime', sqlmodel.sql.sqltypes.AutoString(length=100), nullable=False),
    sa.Column('size', sa.Integer(), nullable=False),
    sa.Column('width', sa.Integer(), nullable=True),
    sa.Column('height', sa.Integer(), nullable=True),
    sa.Column('thumb_url', sqlmodel.sql.sqltypes.AutoString(length=500), nullable=True),
    sa.Column('purpose', sqlmodel.sql.sqltypes.AutoString(length=20), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('media')
    # ### end Alembic commands ###
