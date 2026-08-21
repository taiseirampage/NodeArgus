"""add ASN attribution and Amass ASN history

Revision ID: 0007_amass_asn
Revises: 0006_domains_subdomains
Create Date: 2026-08-21
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa


revision: str = "0007_amass_asn"
down_revision: Union[str, None] = "0006_domains_subdomains"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("domains", sa.Column("asn", sa.String(length=16), nullable=True))
    op.add_column("domains", sa.Column("cidr", sa.String(length=64), nullable=True))

    op.create_table(
        "asn_info",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("domain_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asn_number", sa.Integer(), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=True),
        sa.Column("description", sa.String(length=512), nullable=True),
        sa.Column("country", sa.String(length=2), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", "asn_number", name="uq_asn_domain_number"),
    )
    op.create_index("ix_asn_info_domain_id", "asn_info", ["domain_id"])


def downgrade() -> None:
    op.drop_index("ix_asn_info_domain_id", table_name="asn_info")
    op.drop_table("asn_info")
    op.drop_column("domains", "cidr")
    op.drop_column("domains", "asn")
