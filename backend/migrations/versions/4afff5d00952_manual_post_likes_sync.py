"""manual_post_likes_sync

Revision ID: 4afff5d00952
Revises: cfc34d448b47
Create Date: 2025-06-01 15:27:36.194151

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4afff5d00952'
down_revision: Union[str, None] = 'cfc34d448b47'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
