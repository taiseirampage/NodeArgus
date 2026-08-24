import asyncio
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints import map as map_endpoint
from app.api.v1.endpoints.map import get_map_assets
from app.db import crud
from app.db.models import Base
from app.db.schemas import IPCreate, PortCreate
from app.scanner.nuclei_wrapper import NucleiVulnerability


@pytest_asyncio.fixture
async def map_database() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    yield session_factory
    await engine.dispose()


@pytest.fixture(autouse=True)
def _reset_map_cache() -> Any:
    map_endpoint._cache["at"] = 0.0
    map_endpoint._cache["payload"] = None
    yield


async def _seed_geolocated(
    db: AsyncSession, ip_address: str, ports: list[int] | None = None
) -> int:
    record = await crud.create_ip(
        db,
        IPCreate(
            ip_address=ip_address,
            country="United States",
            country_code="US",
            city="Mountain View",
            latitude=37.751,
            longitude=-97.822,
        ),
    )
    for port in ports or []:
        await crud.create_port(
            db,
            PortCreate(
                ip_id=record.id, port_number=port, protocol="tcp", service="http"
            ),
        )
    return record.id


@pytest.mark.asyncio
async def test_map_assets_excludes_ips_without_coordinates(
    map_database: async_sessionmaker[AsyncSession],
) -> None:
    async with map_database() as db:
        await _seed_geolocated(db, "198.51.100.7", ports=[80, 443])
        await crud.create_ip(db, IPCreate(ip_address="198.51.100.8"))

        assets = await crud.get_map_assets(db)

    assert len(assets) == 1
    assert assets[0]["ip"] == "198.51.100.7"
    assert assets[0]["latitude"] == 37.751
    assert assets[0]["ports_count"] == 2
    assert assets[0]["max_severity"] is None


@pytest.mark.asyncio
async def test_map_assets_reports_highest_severity(
    map_database: async_sessionmaker[AsyncSession],
) -> None:
    async with map_database() as db:
        ip_id = await _seed_geolocated(db, "198.51.100.9", ports=[443])
        findings = [
            NucleiVulnerability(
                template_id="t-1",
                severity="low",
                name="Low finding",
                description="a",
                matched_at="x",
                found_at=datetime.now(timezone.utc),
            ),
            NucleiVulnerability(
                template_id="t-2",
                severity="critical",
                name="Critical finding",
                description="b",
                matched_at="x",
                found_at=datetime.now(timezone.utc),
            ),
        ]
        await crud.save_vulnerabilities(db, ip_id, findings)

        assets = await crud.get_map_assets(db)

    assert assets[0]["max_severity"] == "critical"


@pytest.mark.asyncio
async def test_map_assets_endpoint_returns_count_and_assets(
    map_database: async_sessionmaker[AsyncSession],
) -> None:
    async with map_database() as db:
        await _seed_geolocated(db, "198.51.100.10", ports=[80])
        response = await get_map_assets(db)

    assert response.count == 1
    assert response.assets[0].ip == "198.51.100.10"
    assert response.assets[0].ports_count == 1
    assert response.assets[0].country == "United States"


@pytest.mark.asyncio
async def test_map_assets_endpoint_uses_cache_within_ttl() -> None:
    db = AsyncMock()
    db_body = [
        {
            "ip": "198.51.100.11",
            "latitude": 1.0,
            "longitude": 2.0,
            "country": None,
            "country_code": None,
            "city": None,
            "ports_count": 0,
            "max_severity": None,
        }
    ]
    with (
        patch(
            "app.api.v1.endpoints.map.crud.get_map_assets",
            new_callable=AsyncMock,
            return_value=db_body,
        ) as crud_mock,
        patch("app.api.v1.endpoints.map.time.monotonic", side_effect=[100.0, 100.0]),
    ):
        first = await get_map_assets(db)
        second = await get_map_assets(db)
        assert first.count == 1
        assert second.count == 1
        assert crud_mock.call_count == 1


@pytest.mark.asyncio
async def test_map_assets_endpoint_refreshes_after_ttl() -> None:
    db = AsyncMock()
    with (
        patch(
            "app.api.v1.endpoints.map.crud.get_map_assets",
            new_callable=AsyncMock,
            return_value=[
                {
                    "ip": "198.51.100.12",
                    "latitude": 1.0,
                    "longitude": 2.0,
                    "ports_count": 0,
                    "max_severity": None,
                }
            ],
        ) as crud_mock,
        patch(
            "app.api.v1.endpoints.map.time.monotonic",
            side_effect=[100.0, 100.0, 400.0],
        ),
    ):
        first = await get_map_assets(db)
        within_ttl = await get_map_assets(db)
        after_ttl = await get_map_assets(db)
        assert first.count == 1
        assert within_ttl.count == 1
        assert after_ttl.count == 1
        assert crud_mock.call_count == 2
