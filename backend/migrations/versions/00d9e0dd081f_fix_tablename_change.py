"""FIX Tablename change

Revision ID: 00d9e0dd081f
Revises: a8af7d8a7b22
Create Date: 2025-05-11 09:35:47.195394

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '00d9e0dd081f'
down_revision: Union[str, None] = 'a8af7d8a7b22'
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
    
