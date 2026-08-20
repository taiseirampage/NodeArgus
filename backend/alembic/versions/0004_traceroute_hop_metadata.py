"""mark traceroute hop nodes

Revision ID: 0004_traceroute_hop_metadata
Revises: 0003_nmap_metadata
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0004_traceroute_hop_metadata"
down_revision: Union[str, None] = "0003_nmap_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ips",
        sa.Column(
            "is_traceroute_hop",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
    )
    op.add_column("ips", sa.Column("traceroute_hop", sa.Integer(), nullable=True))
    op.add_column(
        "ips", sa.Column("traceroute_rtt", sa.String(length=32), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("ips", "traceroute_rtt")
    op.drop_column("ips", "traceroute_hop")
    op.drop_column("ips", "is_traceroute_hop")
