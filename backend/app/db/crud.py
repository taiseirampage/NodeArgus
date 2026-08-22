from datetime import datetime, timezone
import ipaddress
import logging
from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.geo.geoip import GeoIPService
from app.geo.models import GeoLocation
from app.scanner.models import NmapResult

from app.scanner.nuclei_wrapper import NucleiVulnerability

from .models import (
    ASNInfo,
    IP,
    Domain,
    Endpoint,
    Link,
    Port,
    Subdomain,
    WebTech,
    subdomain_ip_link,
    Vulnerability,
)
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
        "has_anonymous_access": result.has_anonymous_access,
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


async def save_recon_results(
    db: AsyncSession, domain_name: str, subdomains: list[dict[str, object]]
) -> dict[str, int]:
    """Persist a root domain, its subdomains, and resolved IP links idempotently.

    Each ``subdomains`` entry is expected to have at least a ``name`` string and
    may include ``source`` (the passive source that found it) and
    ``ip_addresses`` (a list of resolved A/AAAA records). Rows are inserted with
    PostgreSQL ``INSERT ... ON CONFLICT DO NOTHING`` so a re-run never
    duplicates rows or links.

    Args:
        db: The active async session.
        domain_name: The validated root FQDN.
        subdomains: Discovered subdomain records with optional sources and IPs.

    Returns:
        A dict summarizing counts of domains, subdomains, and links saved.
    """
    domain_id = await _upsert_domain(db, domain_name)

    saved_subdomains = 0
    saved_links = 0
    for entry in subdomains:
        raw_name = entry.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            continue
        name = raw_name.strip().rstrip(".").lower()
        raw_source = entry.get("source")
        source = str(raw_source) if isinstance(raw_source, str) else None

        sub_id, created = await _upsert_subdomain(db, domain_id, name, source)
        if sub_id is None:
            continue
        if created:
            saved_subdomains += 1

        ip_values = entry.get("ip_addresses")
        if not isinstance(ip_values, list) or not ip_values:
            continue
        for raw_ip in ip_values:
            if not isinstance(raw_ip, str):
                continue
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                logger.warning("Ignoring invalid resolved IP for %s: %s", name, raw_ip)
                continue
            ip_id = await _upsert_ip(db, ip)
            if await _link_subdomain_ip(db, sub_id, ip_id):
                saved_links += 1

    await db.commit()
    logger.info(
        "Recon saved for %s: %d subdomains, %d links",
        domain_name,
        saved_subdomains,
        saved_links,
    )
    return {"domains": 1, "subdomains": saved_subdomains, "links": saved_links}


async def _upsert_domain(db: AsyncSession, name: str) -> Any:
    """Return the id of a domain, inserting the row if it does not exist."""
    result = await db.execute(
        pg_insert(Domain)
        .values(name=name)
        .on_conflict_do_nothing(index_elements=[Domain.name])
        .returning(Domain.id)
    )
    domain_id = result.scalar_one_or_none()
    if domain_id is None:
        existing = await db.execute(select(Domain.id).where(Domain.name == name))
        domain_id = existing.scalar_one()
    return domain_id


async def _upsert_subdomain(
    db: AsyncSession, domain_id: Any, name: str, source: str | None
) -> tuple[Any | None, bool]:
    """Return ``(subdomain id, created)``, inserting the row when it is new.

    The ``created`` flag is ``True`` only when the row was actually inserted by
    this call, so callers can count newly discovered subdomains accurately.
    """
    result = await db.execute(
        pg_insert(Subdomain)
        .values(domain_id=domain_id, name=name, source=source)
        .on_conflict_do_nothing(index_elements=[Subdomain.domain_id, Subdomain.name])
        .returning(Subdomain.id)
    )
    sub_id = result.scalar_one_or_none()
    if sub_id is not None:
        return sub_id, True
    existing = await db.execute(
        select(Subdomain.id).where(
            Subdomain.domain_id == domain_id, Subdomain.name == name
        )
    )
    return existing.scalar_one_or_none(), False


async def _upsert_ip(db: AsyncSession, ip: str) -> Any:
    """Return the id of an IP record, inserting a minimal row when new."""
    record = await get_ip_by_address(db, ip)
    if record is not None:
        return record.id
    created = IP(ip_address=ip)
    db.add(created)
    await db.flush()
    return created.id


async def _link_subdomain_ip(db: AsyncSession, sub_id: Any, ip_id: Any) -> bool:
    """Link a subdomain to an IP idempotently; return True when newly linked."""
    result = await db.execute(
        pg_insert(subdomain_ip_link)
        .values(subdomain_id=sub_id, ip_id=ip_id)
        .on_conflict_do_nothing(
            index_elements=[
                subdomain_ip_link.c.subdomain_id,
                subdomain_ip_link.c.ip_id,
            ]
        )
    )
    return bool(result.rowcount and result.rowcount > 0)


async def get_domain_by_name(db: AsyncSession, name: str) -> Domain | None:
    """Return a root domain record by its validated FQDN."""
    result = await db.execute(select(Domain).where(Domain.name == name))
    return result.scalar_one_or_none()


async def get_domain_subdomains(db: AsyncSession, domain_id: Any) -> list[Subdomain]:
    """Return all subdomains belonging to a domain."""
    result = await db.execute(select(Subdomain).where(Subdomain.domain_id == domain_id))
    return list(result.scalars().all())


async def get_domain_ips(db: AsyncSession, domain_name: str) -> list[str]:
    """Return the unique IP addresses directly linked to a domain's subdomains.

    One subdomain may resolve to several IPs and a shared host (e.g. a CDN)
    backends many subdomains, so the join is deduplicated.
    """
    statement = (
        select(IP.ip_address)
        .join(subdomain_ip_link, subdomain_ip_link.c.ip_id == IP.id)
        .join(Subdomain, Subdomain.id == subdomain_ip_link.c.subdomain_id)
        .join(Domain, Domain.id == Subdomain.domain_id)
        .where(Domain.name == domain_name)
        .distinct()
    )
    result = await db.execute(statement)
    return [str(row[0]) for row in result.all()]


def _merge_source(existing: str | None, new: str) -> str:
    """Return a comma-separated de-duplicated merge of two source labels."""
    parts: list[str] = []
    seen: set[str] = set()
    for raw in (existing or "").split(",") + new.split(","):
        label = raw.strip()
        if not label or label in seen:
            continue
        seen.add(label)
        parts.append(label)
    return ",".join(parts)


async def _upsert_subdomain_with_source(
    db: AsyncSession,
    domain_id: Any,
    name: str,
    source: str,
) -> tuple[Any | None, bool]:
    """Upsert a subdomain, merging ``source`` labels into the stored value.

    The same subdomain is often discovered by several tools (Subfinder's passive
    sources and Amass). This merges the requested labels into the stored
    ``source`` column instead of overwriting it, so provenance is preserved
    (e.g. ``crtsh,amass``). Returns ``(subdomain id, created)``.
    """
    insert = (
        pg_insert(Subdomain)
        .values(domain_id=domain_id, name=name, source=source)
        .on_conflict_do_nothing(index_elements=[Subdomain.domain_id, Subdomain.name])
        .returning(Subdomain.id)
    )
    result = await db.execute(insert)
    sub_id = result.scalar_one_or_none()
    if sub_id is not None:
        return sub_id, True

    existing = await db.execute(
        select(Subdomain).where(
            Subdomain.domain_id == domain_id, Subdomain.name == name
        )
    )
    subdomain = existing.scalar_one_or_none()
    if subdomain is None:
        return None, False
    seen = {
        label.strip() for label in (subdomain.source or "").split(",") if label.strip()
    }
    missing = [label for label in source.split(",") if label not in seen]
    if missing:
        subdomain.source = _merge_source(subdomain.source, ",".join(missing))
        await db.flush()
    return subdomain.id, False


async def _upsert_asn_info(
    db: AsyncSession, domain_id: Any, asn_entry: dict[str, object]
) -> bool:
    """Insert an ASN record idempotently; return True when newly inserted."""
    asn_number = asn_entry.get("asn_number")
    if not isinstance(asn_number, int):
        return False
    result = await db.execute(
        pg_insert(ASNInfo)
        .values(
            domain_id=domain_id,
            asn_number=asn_number,
            cidr=asn_entry.get("cidr"),
            description=asn_entry.get("description"),
            country=asn_entry.get("country"),
        )
        .on_conflict_do_nothing(index_elements=[ASNInfo.domain_id, ASNInfo.asn_number])
    )
    return bool(result.rowcount and result.rowcount > 0)


async def save_amass_results(
    db: AsyncSession,
    domain_name: str,
    amass_result: dict[str, Any],
) -> dict[str, int]:
    """Persist Amass recon output (subdomains, IPs, ASN) idempotently.

    Subdomains are upserted with source merge so rows already created by
    Subfinder are updated to also list ``amass`` rather than being replaced.
    Domain-level ASN/CIDR attribution and per-ASN history rows are stored in the
    ``domains`` and ``asn_info`` tables respectively.

    Args:
        db: The active async session.
        domain_name: The validated root FQDN.
        amass_result: Output of ``run_amass`` with ``subdomains``, ``asn_info``
            and ``ip_addresses`` keys.

    Returns:
        A dict summarizing the number of subdomains, IP links, and ASN records
        saved.
    """
    domain_id = await _upsert_domain(db, domain_name)

    raw_resolved = amass_result.get("resolved")
    raw_asns = amass_result.get("asn_info")
    resolved_map: dict[str, list[str]] = (
        {
            str(name): [item for item in ips if isinstance(item, str)]
            for name, ips in raw_resolved.items()
            if isinstance(name, str) and isinstance(ips, list)
        }
        if isinstance(raw_resolved, dict)
        else {}
    )
    asn_entries: list[dict[str, Any]] = [
        item
        for item in (raw_asns if isinstance(raw_asns, list) else [])
        if isinstance(item, dict)
    ]

    saved_links = 0
    for name, resolved_ips in resolved_map.items():
        sub_id, _ = await _upsert_subdomain_with_source(
            db, domain_id, name.strip().rstrip(".").lower(), "amass"
        )
        if sub_id is None:
            continue
        for raw_ip in resolved_ips:
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                logger.warning("Ignoring invalid Amass IP: %s", raw_ip)
                continue
            ip_id = await _upsert_ip(db, ip)
            if await _link_subdomain_ip(db, sub_id, ip_id):
                saved_links += 1

    saved_asn = 0
    for entry in asn_entries:
        if await _upsert_asn_info(db, domain_id, entry):
            saved_asn += 1

    await db.commit()
    logger.info(
        "Amass results saved for %s: %d IP links, %d ASN records",
        domain_name,
        saved_links,
        saved_asn,
    )
    return {
        "subdomains": len(resolved_map),
        "ip_links": saved_links,
        "asn_records": saved_asn,
    }


async def _apply_domain_asn(
    db: AsyncSession, domain_id: Any, asn_info: list[dict[str, Any]]
) -> int:
    """Persist ASN attribution for a domain and return the number of new rows.

    Stores the best-known ASN/CIDR/organisation on the root ``Domain`` row and
    keeps a per-ASN history row in ``asn_info`` for graph visualisation.
    """
    saved_asn = 0
    for entry in asn_info:
        if await _upsert_asn_info(db, domain_id, entry):
            saved_asn += 1

    primary = next(
        (
            entry
            for entry in asn_info
            if isinstance(entry.get("asn_number"), int) and entry.get("asn_number")
        ),
        None,
    )
    if primary is None:
        return saved_asn

    domain = await db.get(Domain, domain_id)
    if domain is None:
        return saved_asn
    asn_number = int(primary["asn_number"])
    if domain.asn is None:
        domain.asn = str(asn_number)
    if domain.cidr is None and isinstance(primary.get("cidr"), str):
        domain.cidr = primary["cidr"]
    if domain.org_name is None and isinstance(primary.get("description"), str):
        domain.org_name = primary["description"]
    return saved_asn


async def save_unified_recon_results(
    db: AsyncSession,
    domain_name: str,
    subdomains: list[dict[str, Any]],
    asn_info: list[dict[str, Any]] | None = None,
) -> dict[str, int]:
    """Persist de-duplicated multi-tool recon output in one pass.

    The merge coordinator passes a list of unique subdomain records, each with
    ``name``, a list of ``sources`` (tool labels, e.g. ``["subfinder","amass"]``)
    and ``ip_addresses``. Subdomains already present from an earlier Subfinder or
    Amass run are updated to merge the new source labels, so no duplicates are
    ever created and shared discoveries keep all provenance.

    Args:
        db: The active async session.
        domain_name: The validated root FQDN.
        subdomains: Unique subdomain records with merged source labels.
        asn_info: Optional ASN attribution records to merge onto the domain.

    Returns:
        A dict with counts of subdomains, IP links, and ASN records saved.
    """
    domain_id = await _upsert_domain(db, domain_name)

    saved_subdomains = 0
    saved_links = 0
    for entry in subdomains:
        raw_name = entry.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            continue
        name = raw_name.strip().rstrip(".").lower()
        raw_sources = entry.get("sources")
        sources = (
            [str(label) for label in raw_sources if isinstance(label, str)]
            if isinstance(raw_sources, list)
            else []
        )
        if not sources:
            sources = ["subfinder"]

        sub_id, created = await _upsert_subdomain_with_source(
            db, domain_id, name, ",".join(sources)
        )
        if sub_id is None:
            continue
        if created:
            saved_subdomains += 1

        ip_values = entry.get("ip_addresses")
        if not isinstance(ip_values, list) or not ip_values:
            continue
        for raw_ip in ip_values:
            if not isinstance(raw_ip, str):
                continue
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                logger.warning("Ignoring invalid resolved IP for %s: %s", name, raw_ip)
                continue
            ip_id = await _upsert_ip(db, ip)
            if await _link_subdomain_ip(db, sub_id, ip_id):
                saved_links += 1

    saved_asn = 0
    if asn_info:
        saved_asn = await _apply_domain_asn(db, domain_id, asn_info)

    await db.commit()
    logger.info(
        "Unified recon saved for %s: %d subdomains, %d links, %d ASNs",
        domain_name,
        saved_subdomains,
        saved_links,
        saved_asn,
    )
    return {
        "subdomains": saved_subdomains,
        "ip_links": saved_links,
        "asn_records": saved_asn,
    }


async def get_ips_with_web_ports(
    db: AsyncSession,
    ip_addresses: list[str],
    web_ports: set[int] | list[int] | frozenset[int],
) -> list[str]:
    """Return the subset of ``ip_addresses`` that have an open web port.

    Only hosts already audited by Masscan/Nmap are considered, so httpx and
    katana are never pointed at arbitrary addresses — this enforces the "web
    recon runs only on hosts with live HTTP/HTTPS services" pipeline rule.

    Args:
        db: The active async session.
        ip_addresses: Candidate IP strings.
        web_ports: Port numbers to treat as web services.

    Returns:
        The de-duplicated list of IP strings that have at least one matching
        open port.
    """
    if not ip_addresses:
        return []
    port_numbers = [int(port) for port in web_ports]
    statement = (
        select(IP.ip_address)
        .join(Port, Port.ip_id == IP.id)
        .where(IP.ip_address.in_(ip_addresses), Port.port_number.in_(port_numbers))
        .distinct()
    )
    result = await db.execute(statement)
    return [str(row[0]) for row in result.all()]


async def get_ip_id_by_hostname(db: AsyncSession, hostname: str) -> Any | None:
    """Return the id of an IP record linked to a subdomain hostname."""
    statement = (
        select(IP.id)
        .join(subdomain_ip_link, subdomain_ip_link.c.ip_id == IP.id)
        .join(Subdomain, Subdomain.id == subdomain_ip_link.c.subdomain_id)
        .where(Subdomain.name == hostname.rstrip("."))
        .limit(1)
    )
    result = await db.execute(statement)
    return result.scalar_one_or_none()


async def get_or_create_ip_id(db: AsyncSession, ip: str) -> Any:
    """Return the id of an IP record, inserting a minimal row when new."""
    return await _upsert_ip(db, ip)


async def save_web_recon_result(
    db: AsyncSession,
    web_records: list[dict[str, Any]],
) -> dict[str, int]:
    """Persist httpx web probes and their katana endpoints for some IP records.

    Existing ``web_techs`` and ``endpoints`` rows for the affected IPs are
    replaced so a re-run never duplicates probes or crawled URLs. Each
    ``web_records`` entry is a dict with ``ip_id``, ``url``, ``status_code``,
    ``title``, ``technologies`` (list), ``web_server`` and ``endpoints`` (list
    of ``{"path", "method", "source"}``).

    Args:
        db: The active async session.
        web_records: Normalized web probes with their crawled endpoints.

    Returns:
        A dict summarizing the number of web techs and endpoints saved.
    """
    ip_ids = {
        int(record["ip_id"])
        for record in web_records
        if record.get("ip_id") is not None
    }
    if ip_ids:
        web_tech_ids = select(WebTech.id).where(WebTech.ip_id.in_(ip_ids))
        await db.execute(delete(Endpoint).where(Endpoint.web_tech_id.in_(web_tech_ids)))
        await db.execute(delete(WebTech).where(WebTech.ip_id.in_(ip_ids)))

    saved_web = 0
    saved_endpoints = 0
    for record in web_records:
        web_tech = WebTech(
            ip_id=int(record["ip_id"]),
            url=str(record["url"])[:2048],
            status_code=record.get("status_code"),
            title=record.get("title"),
            technologies=record.get("technologies") or None,
            web_server=record.get("web_server"),
        )
        db.add(web_tech)
        await db.flush()
        saved_web += 1
        endpoints = record.get("endpoints")
        if not isinstance(endpoints, list):
            continue
        for entry in endpoints:
            path = entry.get("path")
            if not isinstance(path, str) or not path.strip():
                continue
            db.add(
                Endpoint(
                    web_tech_id=web_tech.id,
                    path=path.strip()[:2048],
                    method=str(entry.get("method") or "GET")[:16],
                    source=entry.get("source"),
                )
            )
            saved_endpoints += 1

    await db.commit()
    logger.info(
        "Web recon saved: %d web techs, %d endpoints", saved_web, saved_endpoints
    )
    return {"web_techs": saved_web, "endpoints": saved_endpoints}


async def get_web_techs_by_ip(db: AsyncSession, ip_id: int) -> list[WebTech]:
    """Return an IP's web probes with their crawled endpoints loaded."""
    statement = (
        select(WebTech)
        .where(WebTech.ip_id == ip_id)
        .options(selectinload(WebTech.endpoints))
        .order_by(WebTech.id)
    )
    result = await db.execute(statement)
    return list(result.scalars().all())
