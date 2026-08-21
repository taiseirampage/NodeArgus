from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.dialects.postgresql import UUID, INET
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


# Many-to-many bridge between subdomains and IP records. A subdomain can resolve
# to several IPs and one shared host (e.g. a CDN) can serve many subdomains.
subdomain_ip_link = Table(
    "subdomain_ip_link",
    Base.metadata,
    Column(
        "subdomain_id",
        UUID(as_uuid=True),
        ForeignKey("subdomains.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "ip_id",
        Integer,
        ForeignKey("ips.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


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
    scripts_info: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    traceroute: Mapped[list[dict[str, object]] | None] = mapped_column(
        JSON, nullable=True
    )
    is_traceroute_hop: Mapped[bool] = mapped_column(
        nullable=False, server_default=false()
    )
    traceroute_hop: Mapped[int | None] = mapped_column(Integer, nullable=True)
    traceroute_rtt: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    subdomains: Mapped[list["Subdomain"]] = relationship(
        secondary=subdomain_ip_link, back_populates="ip_records"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    service: Mapped[str] = mapped_column(String(128), nullable=False)
    banner: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unknown"
    )

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
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="valid_vulnerability_severity",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_id: Mapped[int] = mapped_column(ForeignKey("ips.id", ondelete="CASCADE"))
    template_id: Mapped[str] = mapped_column(String(255), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(String(4096), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    matched_at: Mapped[str] = mapped_column(String(2048), nullable=False)
    found_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    ip: Mapped[IP] = relationship(back_populates="vulnerabilities")


class Domain(Base):
    """A registered root domain enumerated by passive recon."""

    __tablename__ = "domains"

    id: Mapped[Any] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    name: Mapped[str] = mapped_column(String(253), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", lazy="selectin"
    )


class Subdomain(Base):
    """A subdomain discovered for a root domain by a passive source."""

    __tablename__ = "subdomains"
    __table_args__ = (
        UniqueConstraint("domain_id", "name", name="uq_subdomain_domain_name"),
    )

    id: Mapped[Any] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()
    )
    domain_id: Mapped[Any] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    domain: Mapped[Domain] = relationship(back_populates="subdomains")
    ip_records: Mapped[list[IP]] = relationship(
        secondary=subdomain_ip_link, back_populates="subdomains", lazy="selectin"
    )
