"""store Nmap scripts and traceroute metadata

Revision ID: 0003_nmap_metadata
Revises: 0002_vulnerability_fields
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_nmap_metadata"
down_revision: Union[str, None] = "0002_vulnerability_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("ips", sa.Column("scripts_info", sa.JSON(), nullable=True))
    op.add_column("ips", sa.Column("traceroute", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("ips", "scripts_info")
    op.drop_column("ips", "traceroute")
