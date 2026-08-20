from datetime import datetime, timezone
import ipaddress
import logging

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.geo.models import GeoLocation
from app.scanner.models import NmapResult

from .models import IP, Link, Port
from .schemas import IPCreate, LinkCreate, PortCreate


logger = logging.getLogger(__name__)
DEFAULT_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-proxy",
}


async def create_ip(db: AsyncSession, ip: IPCreate) -> IP:
    """Create an IP record and return the persisted ORM object."""
    record = IP(**ip.model_dump())
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_ip_by_address(db: AsyncSession, ip_address: str) -> IP | None:
    """Return an IP record by its PostgreSQL INET address."""
    statement = select(IP).where(IP.ip_address == ip_address)
    result = await db.execute(statement)
    return result.scalar_one_or_none()


async def create_port(db: AsyncSession, port: PortCreate) -> Port:
    """Create a port record and return the persisted ORM object."""
    record = Port(**port.model_dump())
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


async def get_ports_by_ip(db: AsyncSession, ip_id: int) -> list[Port]:
    """Return all ports belonging to an IP record."""
    statement = select(Port).where(Port.ip_id == ip_id).order_by(Port.port_number)
    result = await db.execute(statement)
    return list(result.scalars().all())


async def create_link(db: AsyncSession, link: LinkCreate) -> Link:
    """Create a non-subnet relationship between two IP records."""
    if link.link_type == "same_subnet":
        raise ValueError("same_subnet links must be calculated dynamically")
    record = Link(**link.model_dump())
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


def _scan_ip(target: str) -> str:
    first_target = target.split(",", maxsplit=1)[0].strip()
    try:
        return str(ipaddress.ip_address(first_target))
    except ValueError:
        try:
            return str(ipaddress.ip_network(first_target, strict=False).network_address)
        except ValueError as error:
            raise ValueError(
                "scan result target must contain a valid IP or CIDR"
            ) from error


async def save_scan_result(
    db: AsyncSession, result: NmapResult, geo: GeoLocation
) -> IP:
    """Create or update an IP and persist all Nmap services and GeoIP data.

    Existing ports for the IP are replaced so repeated scans do not create
    duplicate port rows.
    """
    address = _scan_ip(result.target)
    record = await get_ip_by_address(db, address)
    logger.warning(
        "CRUD save_scan_result: target=%s ip_id=%s services=%d",
        result.target,
        record.id if record else "new",
        len(result.services),
    )
    scan_time = datetime.now(timezone.utc)
    values = {
        "country": geo.country,
        "country_code": geo.country_code,
        "city": geo.city,
        "latitude": geo.latitude,
        "longitude": geo.longitude,
        "provider": geo.isp,
        "os": result.os_detection,
        "last_scan": scan_time,
    }
    if record is None:
        record = IP(ip_address=address, **values)
        db.add(record)
        await db.flush()
    else:
        for field, value in values.items():
            setattr(record, field, value)
        await db.execute(delete(Port).where(Port.ip_id == record.id))

    for service in result.services:
        service_name = (service.service or "").strip()
        if not service_name or service_name.lower() == "unknown":
            service_name = DEFAULT_SERVICES.get(service.port, "unknown")
        db.add(
            Port(
                ip_id=record.id,
                port_number=service.port,
                protocol=service.protocol,
                service=service_name,
                banner=service.version or None,
            )
        )
        logger.warning(
            "CRUD port: ip_id=%d port=%d/%s service=%s",
            record.id,
            service.port,
            service.protocol,
            service_name,
        )
    await db.commit()
    await db.refresh(record)
    logger.warning(
        "CRUD save_scan_result complete: ip=%s ip_id=%d ports_saved=%d",
        record.ip_address,
        record.id,
        len(result.services),
    )
    return record
