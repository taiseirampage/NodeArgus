"""add domains.org_name for ASN attribution

Revision ID: 0008_domain_org_name
Revises: 0007_amass_asn
Create Date: 2026-08-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_domain_org_name"
down_revision: Union[str, None] = "0007_amass_asn"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "domains", sa.Column("org_name", sa.String(length=512), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("domains", "org_name")
