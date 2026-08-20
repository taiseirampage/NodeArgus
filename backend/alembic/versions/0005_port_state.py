"""store Nmap port states

Revision ID: 0005_port_state
Revises: 0004_traceroute_hop_metadata
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0005_port_state"
down_revision: Union[str, None] = "0004_traceroute_hop_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ports",
        sa.Column(
            "state",
            sa.String(length=32),
            server_default="unknown",
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("ports", "state")
