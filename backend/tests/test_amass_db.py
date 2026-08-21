import os
from collections.abc import AsyncGenerator
from urllib.parse import urlsplit, urlunsplit

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db import crud
from app.db.models import ASNInfo, Base, Domain, Subdomain


def _test_db_url() -> str:
    """Return a PostgreSQL URL pointing at a dedicated test database."""
    from app.config import settings

    raw = os.environ.get("POSTGRES_ASYNC_URL", settings.POSTGRES_ASYNC_URL)
    parts = urlsplit(raw)
    db_name = parts.path.strip("/") or "nodeargus"
    test_db = os.environ.get("POSTGRES_TEST_DATABASE", f"{db_name}_test")
    return urlunsplit((parts.scheme, parts.netloc, f"/{test_db}", "", ""))


def _is_postgres_reachable() -> bool:
    try:
        url = _test_db_url()
    except Exception:
        return False
    try:
        import asyncpg  # noqa: F401
    except Exception:
        return False
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or 5432
    if not host:
        return False
    import socket

    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except OSError:
        return False


_REQUIRE_PG = pytest.mark.skipif(
    not _is_postgres_reachable(), reason="PostgreSQL not reachable for Amass DB test"
)


@pytest_asyncio.fixture
async def pg_session() -> AsyncGenerator[AsyncSession, None]:
    url = _test_db_url()
    engine = create_async_engine(url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_amass_results_is_idempotent(pg_session: AsyncSession) -> None:
    amass_result = {
        "subdomains": ["a.example.com", "b.example.com"],
        "resolved": {
            "a.example.com": ["1.2.3.4", "1.2.3.5"],
            "b.example.com": ["1.2.3.4"],
        },
        "ip_addresses": ["1.2.3.4", "1.2.3.5"],
        "asn_info": [{"asn_number": 15169, "cidr": "1.2.3.0/24"}],
    }
    first = await crud.save_amass_results(pg_session, "example.com", amass_result)
    second = await crud.save_amass_results(pg_session, "example.com", amass_result)

    assert first == {"subdomains": 2, "ip_links": 3, "asn_records": 1}
    assert second == {"subdomains": 2, "ip_links": 0, "asn_records": 0}

    result = await pg_session.execute(select(Subdomain))
    assert len(list(result.scalars().all())) == 2
    asn_result = await pg_session.execute(select(ASNInfo))
    assert len(list(asn_result.scalars().all())) == 1


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_amass_results_merges_source_with_subfinder(
    pg_session: AsyncSession,
) -> None:
    subdomains = [
        {"name": "a.example.com", "source": "crtsh", "ip_addresses": ["1.2.3.4"]},
    ]
    await crud.save_recon_results(pg_session, "example.com", subdomains)

    amass_result = {
        "subdomains": ["a.example.com", "b.example.com"],
        "resolved": {
            "a.example.com": ["1.2.3.4"],
            "b.example.com": ["1.2.3.4"],
        },
        "ip_addresses": ["1.2.3.4"],
        "asn_info": [],
    }
    await crud.save_amass_results(pg_session, "example.com", amass_result)

    result = await pg_session.execute(
        select(Subdomain).where(Subdomain.name == "a.example.com")
    )
    sub = result.scalar_one()
    assert sub.source == "crtsh,amass"

    result = await pg_session.execute(
        select(Subdomain).where(Subdomain.name == "b.example.com")
    )
    sub = result.scalar_one()
    assert sub.source == "amass"


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_amass_results_stores_asn_records(pg_session: AsyncSession) -> None:
    amass_result = {
        "subdomains": ["a.example.com"],
        "resolved": {"a.example.com": ["1.2.3.4"]},
        "ip_addresses": ["1.2.3.4"],
        "asn_info": [
            {"asn_number": 15169, "cidr": "1.2.3.0/24", "description": "GOOGLE"},
            {"asn_number": 15169, "cidr": "1.2.3.0/24", "description": "GOOGLE"},
        ],
    }
    counts = await crud.save_amass_results(pg_session, "example.com", amass_result)

    assert counts["asn_records"] == 1
    result = await pg_session.execute(select(ASNInfo))
    asn_rows = list(result.scalars().all())
    assert len(asn_rows) == 1
    assert asn_rows[0].asn_number == 15169


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_unified_recon_results_merges_sources_and_asn(
    pg_session: AsyncSession,
) -> None:
    await crud.save_recon_results(
        pg_session,
        "example.com",
        [{"name": "a.example.com", "source": "crtsh", "ip_addresses": ["1.2.3.4"]}],
    )

    counts = await crud.save_unified_recon_results(
        pg_session,
        "example.com",
        [
            {
                "name": "a.example.com",
                "sources": ["subfinder", "amass"],
                "ip_addresses": ["1.2.3.4", "5.6.7.8"],
            },
            {
                "name": "b.example.com",
                "sources": ["amass"],
                "ip_addresses": ["5.6.7.8"],
            },
        ],
        asn_info=[{"asn_number": 15169, "cidr": "1.2.3.0/24", "description": "GOOGLE"}],
    )

    assert counts["subdomains"] == 1
    assert counts["ip_links"] == 2
    assert counts["asn_records"] == 1

    result = await pg_session.execute(
        select(Subdomain).where(Subdomain.name == "a.example.com")
    )
    sub = result.scalar_one()
    assert sub.source == "crtsh,subfinder,amass"

    domain = await crud.get_domain_by_name(pg_session, "example.com")
    assert domain is not None
    assert domain.asn == "15169"
    assert domain.cidr == "1.2.3.0/24"
    assert domain.org_name == "GOOGLE"


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_unified_recon_results_is_idempotent(
    pg_session: AsyncSession,
) -> None:
    records = [
        {
            "name": "a.example.com",
            "sources": ["subfinder", "amass"],
            "ip_addresses": ["1.2.3.4"],
        }
    ]
    called_fields = {
        "sources": ["subfinder", "amass"],
        "ip_addresses": ["1.2.3.4"],
    }
    from app.db.models import Subdomain

    first = await crud.save_unified_recon_results(
        pg_session, "example.com", records, []
    )
    duplicate = [dict(record) for record in records]
    duplicate[0]["name"] = "a.example.com"
    second = await crud.save_unified_recon_results(
        pg_session, "example.com", duplicate, []
    )
    assert first["subdomains"] == 1
    assert second["subdomains"] == 0
    assert called_fields["sources"] == ["subfinder", "amass"]

    result = await pg_session.execute(select(Subdomain))
    assert len(list(result.scalars().all())) == 1
