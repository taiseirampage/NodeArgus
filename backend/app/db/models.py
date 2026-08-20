from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class InetType(TypeDecorator[str]):
    """Use PostgreSQL INET in production and a SQLite test fallback."""

    impl = INET
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(INET())
        return dialect.type_descriptor(String(45))

    def process_bind_param(self, value: str | None, dialect: Any) -> str | None:
        return str(value) if value is not None else None

    def process_result_value(self, value: Any, dialect: Any) -> str | None:
        return str(value) if value is not None else None


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""


class IP(Base):
    __tablename__ = "ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(InetType(), nullable=False, index=True)
    country: Mapped[str | None] = mapped_column(String(128), nullable=True)
    country_code: Mapped[str | None] = mapped_column(String(2), nullable=True)
    city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(nullable=True)
    longitude: Mapped[float | None] = mapped_column(nullable=True)
    provider: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_scan: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    ports: Mapped[list["Port"]] = relationship(
        back_populates="ip", cascade="all, delete-orphan", lazy="selectin"
    )
    source_links: Mapped[list["Link"]] = relationship(
        foreign_keys="Link.source_ip_id", back_populates="source_ip"
    )
    target_links: Mapped[list["Link"]] = relationship(
        foreign_keys="Link.target_ip_id", back_populates="target_ip"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="ip", cascade="all, delete-orphan"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    service: Mapped[str] = mapped_column(String(128), nullable=False)
    banner: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    ip: Mapped[IP] = relationship(back_populates="ports")


class Link(Base):
    __tablename__ = "links"
    __table_args__ = (
        CheckConstraint("link_type <> 'same_subnet'", name="no_same_subnet_links"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    target_ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    link_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    source_ip: Mapped[IP] = relationship(
        foreign_keys=[source_ip_id], back_populates="source_links"
    )
    target_ip: Mapped[IP] = relationship(
        foreign_keys=[target_ip_id], back_populates="target_links"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str] = mapped_column(String(4096), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    found_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    ip: Mapped[IP] = relationship(back_populates="vulnerabilities")
