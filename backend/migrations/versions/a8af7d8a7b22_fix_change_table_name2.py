"""fix change table name2

Revision ID: a8af7d8a7b22
Revises: 03b73bc9013b
Create Date: 2025-05-10 23:00:31.999141

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a8af7d8a7b22'
down_revision: Union[str, None] = '03b73bc9013b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
