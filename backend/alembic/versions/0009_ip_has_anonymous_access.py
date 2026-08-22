"""add ips.has_anonymous_access from NSE auth scripts

Revision ID: 0009_ip_has_anonymous_access
Revises: 0008_domain_org_name
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_ip_has_anonymous_access"
down_revision: Union[str, None] = "0008_domain_org_name"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "ips",
        sa.Column(
            "has_anonymous_access",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("ips", "has_anonymous_access")
