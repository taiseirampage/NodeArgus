from collections.abc import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db import crud
from app.db.models import Base, Domain, IP, Subdomain, subdomain_ip_link


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


async def _seed_domain(db: AsyncSession, name: str = "example.com") -> None:
    domain = Domain(id=uuid4(), name=name)
    db.add(domain)
    await db.flush()
    sub1 = Subdomain(id=uuid4(), domain_id=domain.id, name="www.example.com")
    sub2 = Subdomain(id=uuid4(), domain_id=domain.id, name="api.example.com")
    ip_a = IP(ip_address="1.2.3.4")
    ip_b = IP(ip_address="5.6.7.8")
    db.add_all([sub1, sub2, ip_a, ip_b])
    await db.flush()
    await db.execute(
        subdomain_ip_link.insert().values(subdomain_id=sub1.id, ip_id=ip_a.id)
    )
    await db.execute(
        subdomain_ip_link.insert().values(subdomain_id=sub1.id, ip_id=ip_b.id)
    )
    await db.execute(
        subdomain_ip_link.insert().values(subdomain_id=sub2.id, ip_id=ip_a.id)
    )
    await db.commit()


@pytest.mark.asyncio
async def test_get_domain_by_name_returns_record(db_session: AsyncSession) -> None:
    await _seed_domain(db_session)

    found = await crud.get_domain_by_name(db_session, "example.com")
    missing = await crud.get_domain_by_name(db_session, "nope.example")

    assert found is not None
    assert found.name == "example.com"
    assert missing is None


@pytest.mark.asyncio
async def test_get_domain_subdomains_lists_children(db_session: AsyncSession) -> None:
    await _seed_domain(db_session)
    domain = await crud.get_domain_by_name(db_session, "example.com")
    assert domain is not None

    subdomains = await crud.get_domain_subdomains(db_session, domain.id)

    assert {sub.name for sub in subdomains} == {
        "www.example.com",
        "api.example.com",
    }


@pytest.mark.asyncio
async def test_get_domain_ips_deduplicates_shared_hosts(
    db_session: AsyncSession,
) -> None:
    await _seed_domain(db_session)

    ips = await crud.get_domain_ips(db_session, "example.com")

    assert sorted(ips) == ["1.2.3.4", "5.6.7.8"]


@pytest.mark.asyncio
async def test_get_domain_ips_empty_for_unknown_domain(
    db_session: AsyncSession,
) -> None:
    assert await crud.get_domain_ips(db_session, "other.example") == []
