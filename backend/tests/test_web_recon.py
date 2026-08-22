import asyncio
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from unittest.mock import AsyncMock, patch

from app.db import crud
from app.db.models import Base, Domain, IP, Subdomain, subdomain_ip_link
from app.db.schemas import IPCreate, PortCreate
from app.tasks.web_recon import (
    _resolve_host_ip_id,
    _run_web_recon,
    _targets_for_domain,
    _targets_for_ip,
)


class _SessionContext:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def __aenter__(self) -> AsyncSession:
        return self._session

    async def __aexit__(self, *args: object) -> None:
        return None


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


def _patch_db(session: AsyncSession) -> Any:
    return patch(
        "app.tasks.web_recon.AsyncSessionLocal",
        return_value=_SessionContext(session),
    )


async def _seed_host(db: AsyncSession, domain: str, subdomain: str, ip: str) -> None:
    """Insert a domain -> subdomain -> resolved-IP link with explicit UUIDs."""
    ip_record = await crud.get_ip_by_address(db, ip)
    if ip_record is None:
        ip_record = await crud.create_ip(db, IPCreate(ip_address=ip))
    domain_row = await crud.get_domain_by_name(db, domain)
    if domain_row is None:
        domain_row = Domain(id=uuid.uuid4(), name=domain)
        db.add(domain_row)
        await db.flush()
    sub = Subdomain(
        id=uuid.uuid4(), domain_id=domain_row.id, name=subdomain, source="crtsh"
    )
    db.add(sub)
    await db.flush()
    await db.execute(
        insert(subdomain_ip_link).values(subdomain_id=sub.id, ip_id=ip_record.id)
    )
    await db.commit()


@pytest.mark.asyncio
async def test_targets_for_ip_uses_open_web_ports_only(
    db_session: AsyncSession,
) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="1.2.3.4"))
    for port, service in ((22, "ssh"), (80, "http"), (443, "https")):
        await crud.create_port(
            db_session,
            PortCreate(
                ip_id=record.id, port_number=port, protocol="tcp", service=service
            ),
        )

    targets = await _targets_for_ip(db_session, "1.2.3.4")

    assert targets == ["http://1.2.3.4:80", "https://1.2.3.4:443"]


@pytest.mark.asyncio
async def test_targets_for_ip_returns_empty_when_only_non_web_ports(
    db_session: AsyncSession,
) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="1.2.3.5"))
    await crud.create_port(
        db_session,
        PortCreate(ip_id=record.id, port_number=22, protocol="tcp", service="ssh"),
    )

    assert await _targets_for_ip(db_session, "1.2.3.5") == []


@pytest.mark.asyncio
async def test_targets_for_domain_includes_domain_and_subdomains(
    db_session: AsyncSession,
) -> None:
    await _seed_host(db_session, "example.com", "www.example.com", "1.2.3.4")
    await _seed_host(db_session, "example.com", "api.example.com", "5.6.7.8")

    targets = await _targets_for_domain(db_session, "example.com")

    assert set(targets) == {"example.com", "www.example.com", "api.example.com"}


@pytest.mark.asyncio
async def test_run_web_recon_skips_ip_without_web_ports(
    db_session: AsyncSession,
) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="1.2.3.9"))
    await crud.create_port(
        db_session,
        PortCreate(ip_id=record.id, port_number=22, protocol="tcp", service="ssh"),
    )

    with (
        _patch_db(db_session),
        patch("app.tasks.web_recon.run_httpx", new_callable=AsyncMock) as httpx_mock,
    ):
        result = await _run_web_recon("1.2.3.9")

    assert result["status"] == "skipped"
    httpx_mock.assert_not_called()


@pytest.mark.asyncio
async def test_run_web_recon_full_flow_for_ip(db_session: AsyncSession) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="5.6.7.8"))
    await crud.create_port(
        db_session,
        PortCreate(ip_id=record.id, port_number=80, protocol="tcp", service="http"),
    )
    httpx_records = [
        {
            "url": "http://5.6.7.8:80",
            "status_code": 200,
            "title": "Site Title",
            "tech": ["nginx", "React"],
            "web_server": "nginx/1.25",
        }
    ]
    katana_records = [
        {
            "endpoint": "http://5.6.7.8:80/admin",
            "method": "GET",
            "source": "http://5.6.7.8:80",
        },
        {
            "endpoint": "http://5.6.7.8:80/api/login",
            "method": "POST",
            "source": "http://5.6.7.8:80/admin",
        },
    ]

    with (
        _patch_db(db_session),
        patch("app.tasks.web_recon.run_httpx", new_callable=AsyncMock) as httpx_mock,
        patch("app.tasks.web_recon.run_katana", new_callable=AsyncMock) as katana_mock,
    ):
        httpx_mock.return_value = httpx_records
        katana_mock.return_value = katana_records
        result = await _run_web_recon("5.6.7.8")

    katana_mock.assert_called_once_with(["http://5.6.7.8:80"])
    assert result["status"] == "success"
    assert result["web_techs"] == 1
    assert result["endpoints"] == 2

    web_techs = await crud.get_web_techs_by_ip(db_session, record.id)
    assert web_techs[0].title == "Site Title"
    assert web_techs[0].technologies == ["nginx", "React"]
    assert web_techs[0].web_server == "nginx/1.25"
    endpoints = web_techs[0].endpoints
    assert {endpoint.path for endpoint in endpoints} == {
        "http://5.6.7.8:80/admin",
        "http://5.6.7.8:80/api/login",
    }
    assert {endpoint.method for endpoint in endpoints} == {"GET", "POST"}


@pytest.mark.asyncio
async def test_run_web_recon_resolve_host_via_domain_subdomains(
    db_session: AsyncSession,
) -> None:
    await _seed_host(db_session, "example.com", "www.example.com", "5.6.7.9")
    httpx_records = [
        {
            "url": "http://www.example.com",
            "status_code": 200,
            "title": "WWW",
            "tech": [],
            "web_server": None,
        }
    ]

    with (
        _patch_db(db_session),
        patch("app.tasks.web_recon.run_httpx", new_callable=AsyncMock) as httpx_mock,
        patch("app.tasks.web_recon.run_katana", new_callable=AsyncMock) as katana_mock,
    ):
        httpx_mock.return_value = httpx_records
        katana_mock.return_value = [
            {
                "endpoint": "http://www.example.com/admin",
                "method": "GET",
                "source": "http://www.example.com",
            }
        ]
        result = await _run_web_recon("example.com")

    assert result["status"] == "success"
    assert result["web_techs"] == 1
    assert result["endpoints"] == 1


@pytest.mark.asyncio
async def test_resolve_host_ip_id_uses_existing_ip(db_session: AsyncSession) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="5.6.7.8"))
    ip_id = await _resolve_host_ip_id(db_session, "5.6.7.8")
    assert ip_id == record.id


@pytest.mark.asyncio
async def test_run_web_recon_caps_endpoints_per_host(db_session: AsyncSession) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="9.9.9.9"))
    await crud.create_port(
        db_session,
        PortCreate(ip_id=record.id, port_number=443, protocol="tcp", service="https"),
    )
    httpx_records = [
        {
            "url": "https://9.9.9.9:443",
            "status_code": 200,
            "title": "T",
            "tech": [],
            "web_server": None,
        }
    ]
    katana_records = [
        {
            "endpoint": f"https://9.9.9.9:443/path{i}",
            "method": "GET",
            "source": "https://9.9.9.9:443",
        }
        for i in range(600)
    ]

    with (
        _patch_db(db_session),
        patch("app.tasks.web_recon.run_httpx", new_callable=AsyncMock) as httpx_mock,
        patch("app.tasks.web_recon.run_katana", new_callable=AsyncMock) as katana_mock,
    ):
        httpx_mock.return_value = httpx_records
        katana_mock.return_value = katana_records
        result = await _run_web_recon("9.9.9.9", max_endpoints_per_host=500)

    assert result["endpoints"] == 500
    web_techs = await crud.get_web_techs_by_ip(db_session, record.id)
    assert len(web_techs[0].endpoints) == 500
