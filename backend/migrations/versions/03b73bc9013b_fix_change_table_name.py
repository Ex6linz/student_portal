"""fix change table name

Revision ID: 03b73bc9013b
Revises: d32b4a3d667c
Create Date: 2025-05-10 22:58:21.273533

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '03b73bc9013b'
down_revision: Union[str, None] = 'd32b4a3d667c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
