"""add domains and subdomains

Revision ID: 0006_domains_subdomains
Revises: 0005_port_state
Create Date: 2026-08-21
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa


revision: str = "0006_domains_subdomains"
down_revision: Union[str, None] = "0005_port_state"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "domains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "subdomains",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("domain_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", "name", name="uq_subdomain_domain_name"),
    )
    op.create_index("ix_subdomains_domain_id", "subdomains", ["domain_id"])
    op.create_index("ix_subdomains_name", "subdomains", ["name"])
    op.create_table(
        "subdomain_ip_link",
        sa.Column("subdomain_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ip_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["subdomain_id"], ["subdomains.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("subdomain_id", "ip_id"),
    )


def downgrade() -> None:
    op.drop_table("subdomain_ip_link")
    op.drop_index("ix_subdomains_name", table_name="subdomains")
    op.drop_index("ix_subdomains_domain_id", table_name="subdomains")
    op.drop_table("subdomains")
    op.drop_table("domains")
