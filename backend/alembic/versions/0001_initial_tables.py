"""initial tables

Revision ID: 0001_initial_tables
Revises:
Create Date: 2026-08-20
"""

from typing import Sequence, Union

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa


revision: str = "0001_initial_tables"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ips",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=False),
        sa.Column("country", sa.String(length=128), nullable=True),
        sa.Column("country_code", sa.String(length=2), nullable=True),
        sa.Column("city", sa.String(length=128), nullable=True),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("provider", sa.String(length=255), nullable=True),
        sa.Column("os", sa.String(length=255), nullable=True),
        sa.Column("last_scan", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ips_ip_address", "ips", ["ip_address"], unique=False)
    op.create_table(
        "ports",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip_id", sa.Integer(), nullable=False),
        sa.Column("port_number", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("service", sa.String(length=128), nullable=False),
        sa.Column("banner", sa.String(length=1024), nullable=True),
        sa.ForeignKeyConstraint(["ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "links",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_ip_id", sa.Integer(), nullable=False),
        sa.Column("target_ip_id", sa.Integer(), nullable=False),
        sa.Column("link_type", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("link_type <> 'same_subnet'", name="no_same_subnet_links"),
        sa.ForeignKeyConstraint(["source_ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=4096), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column(
            "found_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("vulnerabilities")
    op.drop_table("links")
    op.drop_table("ports")
    op.drop_index("ix_ips_ip_address", table_name="ips")
    op.drop_table("ips")
