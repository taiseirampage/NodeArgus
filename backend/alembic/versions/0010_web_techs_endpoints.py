"""web recon tables: web_techs and endpoints

Revision ID: 0010_web_techs_endpoints
Revises: 0009_ip_has_anonymous_access
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_web_techs_endpoints"
down_revision: Union[str, None] = "0009_ip_has_anonymous_access"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "web_techs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ip_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=2048), nullable=True),
        sa.Column("technologies", sa.JSON(), nullable=True),
        sa.Column("web_server", sa.String(length=255), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["ip_id"], ["ips.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_web_techs_ip_id", "web_techs", ["ip_id"], unique=False)
    op.create_table(
        "endpoints",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("web_tech_id", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=16), server_default="GET", nullable=False),
        sa.Column("source", sa.String(length=2048), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["web_tech_id"], ["web_techs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_endpoints_web_tech_id", "endpoints", ["web_tech_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_endpoints_web_tech_id", table_name="endpoints")
    op.drop_table("endpoints")
    op.drop_index("ix_web_techs_ip_id", table_name="web_techs")
    op.drop_table("web_techs")
