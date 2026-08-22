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
    has_anonymous_access: Mapped[bool] = mapped_column(
        nullable=False, server_default=false()
    )
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
    web_techs: Mapped[list["WebTech"]] = relationship(
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
    asn: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    org_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    subdomains: Mapped[list["Subdomain"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", lazy="selectin"
    )
    asn_records: Mapped[list["ASNInfo"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
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


class ASNInfo(Base):
    """Autonomous system information attributed to a root domain by Amass.

    Multiple CIDRs and descriptions can map back to the same ASN number, so the
    uniqueness constraint is scoped per-domain plus the ASN number.
    """

    __tablename__ = "asn_info"
    __table_args__ = (
        UniqueConstraint("domain_id", "asn_number", name="uq_asn_domain_number"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain_id: Mapped[Any] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asn_number: Mapped[int] = mapped_column(Integer, nullable=False)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    domain: Mapped[Domain] = relationship(back_populates="asn_records")


class WebTech(Base):
    """A live web property (httpx probe) attached to an IP record."""

    __tablename__ = "web_techs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_id: Mapped[int] = mapped_column(
        ForeignKey("ips.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    technologies: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    web_server: Mapped[str | None] = mapped_column(String(255), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    ip: Mapped[IP] = relationship(back_populates="web_techs")
    endpoints: Mapped[list["Endpoint"]] = relationship(
        back_populates="web_tech", cascade="all, delete-orphan", lazy="selectin"
    )


class Endpoint(Base):
    """One crawled URL found by katana on a web property."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    web_tech_id: Mapped[int] = mapped_column(
        ForeignKey("web_techs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="GET"
    )
    source: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    web_tech: Mapped[WebTech] = relationship(back_populates="endpoints")
