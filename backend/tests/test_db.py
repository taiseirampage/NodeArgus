from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints.ip import get_ip_details
from app.db import crud
from app.db.models import Base, WebTech
from app.db.schemas import IPCreate, LinkCreate, PortCreate
from app.geo.models import GeoLocation
from app.scanner.models import NmapResult, NmapService


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_ip_with_valid_address(db_session: AsyncSession) -> None:
    record = await crud.create_ip(
        db_session,
        IPCreate(ip_address="192.168.1.1", country="RU", country_code="RU"),
    )

    assert record.id > 0
    assert record.ip_address == "192.168.1.1"


@pytest.mark.asyncio
async def test_get_ip_by_address(db_session: AsyncSession) -> None:
    await crud.create_ip(db_session, IPCreate(ip_address="8.8.8.8"))

    record = await crud.get_ip_by_address(db_session, "8.8.8.8")

    assert record is not None
    assert record.ip_address == "8.8.8.8"


@pytest.mark.asyncio
async def test_get_ip_details_returns_ports(db_session: AsyncSession) -> None:
    record = await crud.create_ip(
        db_session,
        IPCreate(
            ip_address="192.168.1.10",
            country="Russia",
            city="Moscow",
            os="Linux",
            provider="Example ISP",
        ),
    )
    await crud.create_port(
        db_session,
        PortCreate(
            ip_id=record.id,
            port_number=443,
            protocol="tcp",
            service="https",
            banner="nginx",
        ),
    )

    response = await get_ip_details("192.168.1.10", db_session)

    assert response.ip == "192.168.1.10"
    assert response.country == "Russia"
    assert response.ports[0].port_number == 443
    assert response.ports[0].banner == "nginx"


@pytest.mark.asyncio
async def test_get_ip_details_returns_404(db_session: AsyncSession) -> None:
    with pytest.raises(HTTPException) as error:
        await get_ip_details("192.168.1.10", db_session)

    assert error.value.status_code == 404


@pytest.mark.asyncio
async def test_get_ip_details_tolerates_null_web_tech_technologies(
    db_session: AsyncSession,
) -> None:
    record = await crud.create_ip(db_session, IPCreate(ip_address="192.168.1.11"))
    db_session.add(
        WebTech(
            ip_id=record.id,
            url="https://example.com",
            status_code=200,
            title=None,
            technologies=None,
            web_server=None,
        )
    )
    await db_session.commit()

    response = await get_ip_details("192.168.1.11", db_session)

    assert len(response.web_techs) == 1
    assert response.web_techs[0].url == "https://example.com"
    assert response.web_techs[0].technologies == []


@pytest.mark.asyncio
async def test_create_ports_and_links(db_session: AsyncSession) -> None:
    source = await crud.create_ip(db_session, IPCreate(ip_address="10.0.0.1"))
    target = await crud.create_ip(db_session, IPCreate(ip_address="10.0.0.2"))
    port = await crud.create_port(
        db_session,
        PortCreate(
            ip_id=source.id,
            port_number=443,
            protocol="tcp",
            service="https",
        ),
    )
    link = await crud.create_link(
        db_session,
        LinkCreate(
            source_ip_id=source.id,
            target_ip_id=target.id,
            link_type="common_port",
        ),
    )

    ports = await crud.get_ports_by_ip(db_session, source.id)
    assert port.id > 0
    assert link.id > 0
    assert [item.port_number for item in ports] == [443]


@pytest.mark.asyncio
async def test_save_scan_result_persists_geo_and_services(
    db_session: AsyncSession,
) -> None:
    result = NmapResult(
        target="8.8.8.8",
        os_detection="Linux",
        services=[
            NmapService(
                port=443,
                protocol="tcp",
                service="https",
                version="nginx 1.25",
            )
        ],
        scan_time=0.5,
        scripts_output={"http-title": "Title: Example"},
        traceroute=[],
    )
    geo = GeoLocation(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        city="Ashburn",
        latitude=39.0,
        longitude=-77.0,
        timezone="America/New_York",
        isp="Example ISP",
    )

    record = await crud.save_scan_result(db_session, result, geo)
    ports = await crud.get_ports_by_ip(db_session, record.id)

    assert record.country_code == "US"
    assert record.provider == "Example ISP"
    assert record.os == "Linux"
    assert record.scripts_info == {"http-title": "Title: Example"}
    assert record.has_anonymous_access is False
    assert ports[0].banner == "nginx 1.25"


@pytest.mark.asyncio
async def test_save_scan_result_uses_default_service_name(
    db_session: AsyncSession,
) -> None:
    result = NmapResult(
        target="8.8.8.8",
        os_detection="",
        services=[NmapService(port=80, protocol="tcp", service="", version="")],
        scan_time=0.1,
    )

    record = await crud.save_scan_result(db_session, result, GeoLocation(ip="8.8.8.8"))
    ports = await crud.get_ports_by_ip(db_session, record.id)

    assert ports[0].service == "http"


@pytest.mark.asyncio
async def test_save_scan_result_updates_duplicate_ip_without_duplicate_ports(
    db_session: AsyncSession,
) -> None:
    first = NmapResult(
        target="1.1.1.1",
        os_detection="Linux",
        services=[NmapService(port=80, protocol="tcp", service="http", version="1")],
        scan_time=0.1,
    )
    second = NmapResult(
        target="1.1.1.1",
        os_detection="FreeBSD",
        services=[NmapService(port=443, protocol="tcp", service="https", version="2")],
        scan_time=0.1,
    )
    geo = GeoLocation(ip="1.1.1.1")

    first_record = await crud.save_scan_result(db_session, first, geo)
    second_record = await crud.save_scan_result(db_session, second, geo)
    ports = await crud.get_ports_by_ip(db_session, second_record.id)

    assert first_record.id == second_record.id
    assert second_record.os == "FreeBSD"
    assert len(ports) == 1
    assert ports[0].port_number == 443


@pytest.mark.asyncio
async def test_save_scan_result_persists_anonymous_access_flag(
    db_session: AsyncSession,
) -> None:
    result = NmapResult(
        target="8.8.8.8",
        os_detection="",
        services=[NmapService(port=21, protocol="tcp", service="ftp", version="")],
        scan_time=0.1,
        scripts_output={"ftp-anon": "Anonymous FTP login allowed (FTP code 230)"},
        has_anonymous_access=True,
    )

    record = await crud.save_scan_result(db_session, result, GeoLocation(ip="8.8.8.8"))

    assert record.has_anonymous_access is True


@pytest.mark.asyncio
async def test_upsert_ip_applies_geo_location(db_session: AsyncSession) -> None:
    location = GeoLocation(
        ip="8.8.8.8",
        country="United States",
        country_code="US",
        city="Mountain View",
        latitude=37.751,
        longitude=-97.822,
        isp="Example ISP",
    )

    await crud._upsert_ip(db_session, "8.8.8.8", location)
    record = await crud.get_ip_by_address(db_session, "8.8.8.8")

    assert record is not None
    assert record.latitude == 37.751
    assert record.longitude == -97.822
    assert record.country_code == "US"
    assert record.provider == "Example ISP"


@pytest.mark.asyncio
async def test_upsert_ip_backfills_missing_geo(db_session: AsyncSession) -> None:
    await crud._upsert_ip(db_session, "1.1.1.1")
    before = await crud.get_ip_by_address(db_session, "1.1.1.1")
    assert before is not None
    assert before.latitude is None

    await crud._upsert_ip(
        db_session, "1.1.1.1", GeoLocation(ip="1.1.1.1", latitude=1.0, longitude=-1.0)
    )
    after = await crud.get_ip_by_address(db_session, "1.1.1.1")

    assert after is not None
    assert after.latitude == 1.0
    assert after.longitude == -1.0


@pytest.mark.asyncio
async def test_upsert_ip_keeps_existing_geo(db_session: AsyncSession) -> None:
    await crud._upsert_ip(
        db_session, "4.4.4.4", GeoLocation(ip="4.4.4.4", latitude=40.0, longitude=-74.0)
    )
    await crud._upsert_ip(
        db_session, "4.4.4.4", GeoLocation(ip="4.4.4.4", latitude=1.0, longitude=1.0)
    )
    record = await crud.get_ip_by_address(db_session, "4.4.4.4")

    assert record is not None
    assert record.latitude == 40.0
    assert record.longitude == -74.0


class _StubGeoService:
    def __init__(self, mapping: dict[str, GeoLocation]) -> None:
        self._mapping = mapping
        self.calls: list[str] = []

    def lookup(self, ip: str) -> GeoLocation | None:
        self.calls.append(ip)
        return self._mapping.get(ip)


@pytest.mark.asyncio
async def test_backfill_ip_geolocation_geocodes_public_ips(
    db_session: AsyncSession,
) -> None:
    await crud._upsert_ip(db_session, "104.20.2.108")
    await crud._upsert_ip(db_session, "10.0.0.5")
    geo = _StubGeoService(
        {
            "104.20.2.108": GeoLocation(
                ip="104.20.2.108",
                country="US",
                country_code="US",
                city="Unknown",
                latitude=0.0,
                longitude=0.0,
            )
        }
    )
    attempted: set[str] = set()

    updated = await crud.backfill_ip_geolocation(db_session, geo, attempted)

    assert updated == 1
    public = await crud.get_ip_by_address(db_session, "104.20.2.108")
    assert public is not None
    assert public.latitude == 0.0
    assert public.longitude == 0.0
    assert public.country_code == "US"

    private = await crud.get_ip_by_address(db_session, "10.0.0.5")
    assert private is not None
    assert private.latitude is None
    assert private.longitude is None

    # Private IPs and already-attempted hosts are not looked up again.
    second = await crud.backfill_ip_geolocation(db_session, geo, attempted)
    assert second == 0
    assert geo.calls == ["104.20.2.108"]
