import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db import crud
from app.db.models import Base, Domain, Subdomain


def _is_postgres_reachable() -> bool:
    try:
        from app.config import settings
        from urllib.parse import urlsplit
    except Exception:
        return False
    url = os.environ.get("POSTGRES_ASYNC_URL", settings.POSTGRES_ASYNC_URL)
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
    not _is_postgres_reachable(), reason="PostgreSQL not reachable for recon DB test"
)


@pytest_asyncio.fixture
async def pg_session() -> AsyncGenerator[AsyncSession, None]:
    from app.config import settings

    url = os.environ.get("POSTGRES_ASYNC_URL", settings.POSTGRES_ASYNC_URL)
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
async def test_save_recon_results_is_idempotent(pg_session: AsyncSession) -> None:
    subdomains = [
        {"name": "a.example.com", "source": "crtsh", "ip_addresses": ["1.2.3.4"]},
        {"name": "b.example.com", "source": "hackertarget", "ip_addresses": []},
    ]
    first = await crud.save_recon_results(pg_session, "example.com", subdomains)
    second = await crud.save_recon_results(pg_session, "example.com", subdomains)

    assert first == {"domains": 1, "subdomains": 2, "links": 1}
    assert second == {"domains": 1, "subdomains": 0, "links": 0}

    result = await pg_session.execute(select(Subdomain))
    sub_rows = list(result.scalars().all())
    assert len(sub_rows) == 2

    domain_result = await pg_session.execute(
        select(Domain).where(Domain.name == "example.com")
    )
    assert domain_result.scalar_one_or_none() is not None


@_REQUIRE_PG
@pytest.mark.asyncio
async def test_save_recon_results_skips_invalid_ips(pg_session: AsyncSession) -> None:
    subdomains = [
        {
            "name": "c.example.com",
            "source": "alienvault",
            "ip_addresses": ["not-an-ip", "10.0.0.1"],
        },
    ]
    counts = await crud.save_recon_results(pg_session, "example.com", subdomains)
    assert counts == {"domains": 1, "subdomains": 1, "links": 1}
