"""Change table name user to users

Revision ID: d32b4a3d667c
Revises: 4878a8db9bfd
Create Date: 2025-05-10 22:57:04.806593

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd32b4a3d667c'
down_revision: Union[str, None] = '4878a8db9bfd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.rename_table('user', 'users')
    with op.batch_alter_table('refresh_token') as batch_op:
        batch_op.drop_constraint('refresh_token_user_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key('refresh_token_user_id_fkey', 'users', ['user_id'], ['id'])
    


def downgrade() -> None:
    with op.batch_alter_table('refresh_token') as batch_op:
        batch_op.drop_constraint('refresh_token_user_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key('refresh_token_user_id_fkey', 'user', ['user_id'], ['id'])
    
    op.rename_table('users', 'user')
    pass
