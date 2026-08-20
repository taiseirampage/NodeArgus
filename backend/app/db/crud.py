from datetime import datetime, timezone
import ipaddress
import logging

from sqlalchemy import case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.geo.geoip import GeoIPService
from app.geo.models import GeoLocation
from app.scanner.models import NmapResult

from app.scanner.nuclei_wrapper import NucleiVulnerability

from .models import IP, Link, Port, Vulnerability
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


async def get_last_vuln_scan(db: AsyncSession, ip_id: int) -> datetime | None:
    """Return the most recent vulnerability finding timestamp for an IP."""
    statement = select(func.max(Vulnerability.found_at)).where(
        Vulnerability.ip_id == ip_id
    )
    result = await db.execute(statement)
    value = result.scalar_one_or_none()
    return value if isinstance(value, datetime) else None


async def save_vulnerabilities(
    db: AsyncSession, ip_id: int, vulnerabilities: list[NucleiVulnerability]
) -> None:
    """Replace the current finding set for an IP with a Nuclei result set."""
    await db.execute(delete(Vulnerability).where(Vulnerability.ip_id == ip_id))
    for finding in vulnerabilities:
        db.add(
            Vulnerability(
                ip_id=ip_id,
                template_id=finding.template_id,
                cve_id=finding.cve_id,
                name=finding.name,
                description=finding.description,
                severity=finding.severity,
                matched_at=finding.matched_at,
                found_at=finding.found_at,
            )
        )
    await db.commit()
    logger.info("Saved %d vulnerabilities for IP id %d", len(vulnerabilities), ip_id)


async def get_vulnerabilities_by_ip(
    db: AsyncSession, ip_id: int
) -> list[Vulnerability]:
    """Return findings ordered from critical severity down to informational."""
    severity_order = case(
        (Vulnerability.severity == "critical", 0),
        (Vulnerability.severity == "high", 1),
        (Vulnerability.severity == "medium", 2),
        (Vulnerability.severity == "low", 3),
        (Vulnerability.severity == "info", 4),
        else_=5,
    )
    statement = (
        select(Vulnerability)
        .where(Vulnerability.ip_id == ip_id)
        .order_by(
            severity_order, Vulnerability.found_at.desc(), Vulnerability.id.desc()
        )
    )
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
        "scripts_info": result.scripts_output or None,
        "traceroute": [hop.model_dump() for hop in result.traceroute] or None,
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
                state=service.state or "unknown",
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


def _clean_traceroute_hops(
    hops: list[dict[str, object]],
) -> list[tuple[int, str, str | None]]:
    cleaned: list[tuple[int, str, str | None]] = []
    for hop in hops:
        raw_ip = hop.get("ip")
        if not isinstance(raw_ip, str) or raw_ip.lower() in {"*", "unknown"}:
            continue
        try:
            ip = str(ipaddress.ip_address(raw_ip))
            hop_number = int(hop["hop"])
        except (KeyError, TypeError, ValueError):
            logger.warning("Ignoring invalid traceroute hop: %s", hop)
            continue
        raw_rtt = hop.get("rtt")
        rtt = str(raw_rtt) if raw_rtt is not None else None
        cleaned.append((hop_number, ip, rtt))
    return sorted(cleaned, key=lambda item: item[0])


async def _ensure_ip_record(
    db: AsyncSession,
    ip: str,
    geo_service: GeoIPService | None,
    is_hop: bool,
    hop_number: int | None = None,
    rtt: str | None = None,
) -> IP:
    record = await get_ip_by_address(db, ip)
    if record is None:
        location = geo_service.lookup(ip) if geo_service is not None else None
        record = IP(
            ip_address=ip,
            country=location.country if location else None,
            country_code=location.country_code if location else None,
            city=location.city if location else None,
            latitude=location.latitude if location else None,
            longitude=location.longitude if location else None,
            provider=location.isp if location else None,
            is_traceroute_hop=is_hop,
            traceroute_hop=hop_number,
            traceroute_rtt=rtt,
        )
        db.add(record)
        await db.flush()
    elif is_hop and record.is_traceroute_hop:
        record.traceroute_hop = hop_number
        record.traceroute_rtt = rtt
    return record


async def save_traceroute_hops(
    db: AsyncSession, target_ip: str, hops: list[dict[str, object]]
) -> None:
    """Persist responsive traceroute hops and their ordered graph links."""
    target = str(ipaddress.ip_address(target_ip))
    cleaned_hops = _clean_traceroute_hops(hops)
    if not cleaned_hops:
        return

    geo_service: GeoIPService | None = None
    try:
        try:
            geo_service = GeoIPService(settings.GEOIP_DB_PATH)
        except (FileNotFoundError, RuntimeError) as error:
            logger.warning("GeoIP unavailable for traceroute hops: %s", error)

        target_record = await _ensure_ip_record(db, target, geo_service, False)
        hop_records = [
            await _ensure_ip_record(db, ip, geo_service, True, hop_number, rtt)
            for hop_number, ip, rtt in cleaned_hops
        ]
        chain = [record for record in hop_records if record.id != target_record.id]
        chain.append(target_record)
        pairs = [
            (source.id, destination.id)
            for source, destination in zip(chain, chain[1:])
            if source.id != destination.id
        ]
        if not pairs:
            return
        ids = {item for pair in pairs for item in pair}
        existing_result = await db.execute(
            select(Link.source_ip_id, Link.target_ip_id).where(
                Link.link_type == "traceroute_hop",
                Link.source_ip_id.in_(ids),
                Link.target_ip_id.in_(ids),
            )
        )
        existing = set(existing_result.all())
        for source_id, target_id in pairs:
            if (source_id, target_id) not in existing:
                db.add(
                    Link(
                        source_ip_id=source_id,
                        target_ip_id=target_id,
                        link_type="traceroute_hop",
                    )
                )
        await db.commit()
        logger.info("Saved %d traceroute links for %s", len(pairs), target)
    finally:
        if geo_service is not None:
            geo_service.close()
