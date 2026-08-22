import csv
import io
import ipaddress
import logging
from collections.abc import AsyncIterable
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db.models import Endpoint, IP, Port, Vulnerability, WebTech
from app.scanner.validator import validate_domain, validate_target


router = APIRouter()
logger = logging.getLogger(__name__)


class _TargetKind:
    IP = "ip"
    DOMAIN = "domain"


def _safe_filename(value: str) -> str:
    return "".join(
        char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value
    ).strip("._")


def _resolve_target(target: str) -> tuple[str, str]:
    """Return ``(normalized, kind)`` for an IP or domain target, or raise 400."""
    value = target.strip()
    try:
        normalized_ip = validate_target(value)
        if "," in normalized_ip or "/" in normalized_ip:
            raise ValueError("a single IP address is required")
        normalized_ip = str(ipaddress.ip_address(normalized_ip))
        return normalized_ip, _TargetKind.IP
    except ValueError:
        pass
    try:
        return validate_domain(value), _TargetKind.DOMAIN
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target must be a valid IP address or fully qualified domain name",
        ) from error


async def _resolve_ip_records(db: AsyncSession, ip_strings: list[str]) -> list[IP]:
    """Load IP records for the provided addresses, skipping unknown ones."""
    records: list[IP] = []
    seen: set[str] = set()
    for address in ip_strings:
        if address in seen:
            continue
        seen.add(address)
        record = await crud.get_ip_by_address(db, address)
        if record is not None:
            records.append(record)
    return records


async def _target_ip_records(
    db: AsyncSession, target: str
) -> tuple[list[IP], str, str]:
    """Resolve the IP records a target refers to; raise 404 when absent.

    A single IP target maps to itself; a domain target maps to the unique IPs
    resolved from its subdomains.

    Args:
        db: The active async session.
        target: A validated IP or domain string.

    Returns:
        ``(ip_records, normalized_target, kind)``.

    Raises:
        HTTPException: 404 when the target is not present in the database.
    """
    normalized, kind = _resolve_target(target)
    if kind == _TargetKind.IP:
        record = await crud.get_ip_by_address(db, normalized)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="IP not found in database",
            )
        return [record], normalized, kind

    domain = await crud.get_domain_by_name(db, normalized)
    if domain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found in database",
        )
    ip_strings = await crud.get_domain_ips(db, normalized)
    records = await _resolve_ip_records(db, ip_strings)
    return records, normalized, kind


def _port_json(ip_address: str, port: Port) -> dict[str, Any]:
    return {
        "ip": ip_address,
        "port": port.port_number,
        "protocol": port.protocol,
        "state": port.state,
        "service": port.service,
        "banner": port.banner,
    }


def _vuln_json(ip_address: str, vulnerability: Vulnerability) -> dict[str, Any]:
    return {
        "ip": ip_address,
        "template_id": vulnerability.template_id,
        "cve_id": vulnerability.cve_id,
        "name": vulnerability.name,
        "severity": vulnerability.severity,
        "matched_at": vulnerability.matched_at,
        "found_at": vulnerability.found_at.isoformat(),
        "description": vulnerability.description,
    }


def _endpoint_json(
    ip_address: str, web_tech: WebTech, endpoint: Endpoint
) -> dict[str, Any]:
    return {
        "ip": ip_address,
        "web_url": web_tech.url,
        "url": endpoint.path,
        "method": endpoint.method,
        "source": endpoint.source,
        "discovered_at": endpoint.discovered_at.isoformat(),
    }


async def _ip_report_payload(db: AsyncSession, record: IP) -> dict[str, Any]:
    """Build the nested full-report payload for one IP, loading children async."""
    ports = await crud.get_ports_by_ip(db, record.id)
    vulnerabilities = await crud.get_vulnerabilities_by_ip(db, record.id)
    web_techs = await crud.get_web_techs_by_ip(db, record.id)
    ip_address = str(record.ip_address)
    return {
        "ip": ip_address,
        "country": record.country,
        "country_code": record.country_code,
        "city": record.city,
        "latitude": record.latitude,
        "longitude": record.longitude,
        "provider": record.provider,
        "os": record.os,
        "has_anonymous_access": record.has_anonymous_access,
        "nse_scripts": record.scripts_info or {},
        "traceroute": record.traceroute or [],
        "ports": [_port_json(ip_address, port) for port in ports],
        "vulnerabilities": [_vuln_json(ip_address, vuln) for vuln in vulnerabilities],
        "web_techs": [
            {
                "url": tech.url,
                "status_code": tech.status_code,
                "title": tech.title,
                "technologies": tech.technologies or [],
                "web_server": tech.web_server,
                "discovered_at": tech.discovered_at.isoformat(),
                "endpoints": [
                    _endpoint_json(ip_address, tech, endpoint)
                    for endpoint in tech.endpoints
                ],
            }
            for tech in web_techs
        ],
    }


@router.get("/{target}/full", response_class=JSONResponse)
async def export_full_report(
    target: str, db: AsyncSession = Depends(get_db)
) -> JSONResponse:
    """Export a complete nested report (IP or domain) as JSON.

    For an IP the payload holds geo metadata, NSE scripts, traceroute, ports,
    Nuclei findings and httpx/katana web data. For a domain it nests the
    subdomain structure plus the same per-IP payloads, so relational data is
    never flattened into a single table.

    Args:
        target: A validated IP or fully qualified domain name.
        db: The active async session.

    Returns:
        A JSON response with an ``attachment`` content disposition.
    """
    records, normalized, kind = await _target_ip_records(db, target)
    exported_at = datetime.now(timezone.utc).isoformat()
    ip_payloads = [await _ip_report_payload(db, record) for record in records]
    payload: dict[str, Any] = {
        "target": normalized,
        "target_type": kind,
        "exported_at": exported_at,
        "ips": ip_payloads,
    }
    if kind == _TargetKind.DOMAIN:
        domain = await crud.get_domain_by_name(db, normalized)
        if domain is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not found in database",
            )
        subdomains = await crud.get_domain_subdomains(db, domain.id)
        payload["domain"] = {
            "name": domain.name,
            "asn": domain.asn,
            "cidr": domain.cidr,
            "org_name": domain.org_name,
        }
        payload["subdomains"] = [
            {
                "name": subdomain.name,
                "source": subdomain.source,
                "resolved_ips": [
                    str(record.ip_address) for record in subdomain.ip_records
                ],
            }
            for subdomain in subdomains
        ]

    filename = f"nodeargus_{_safe_filename(normalized)}_{kind}_report.json"
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


async def _csv_chunks(header: list[str], rows: Any) -> AsyncIterator[str]:
    """Stream CSV rows in bounded chunks without buffering the whole file.

    ``rows`` is an async iterable (an async generator) so the backing SQL
    queries are executed lazily as the response streams.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    flushed = False
    async for row in rows:
        writer.writerow(["" if value is None else value for value in row])
        if buffer.tell() > 8192:
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            flushed = True
    if flushed or buffer.tell() > 0:
        yield buffer.getvalue()


async def _iter_port_rows(
    db: AsyncSession, records: list[IP]
) -> AsyncIterable[list[Any]]:
    for record in records:
        ip_address = str(record.ip_address)
        ports = await crud.get_ports_by_ip(db, record.id)
        for port in ports:
            yield [
                ip_address,
                f"{port.port_number}/{port.protocol}",
                port.state,
                port.service,
                port.banner or "",
            ]


async def _iter_vuln_rows(
    db: AsyncSession, records: list[IP]
) -> AsyncIterable[list[Any]]:
    for record in records:
        ip_address = str(record.ip_address)
        findings = await crud.get_vulnerabilities_by_ip(db, record.id)
        for finding in findings:
            yield [
                ip_address,
                finding.cve_id or finding.template_id,
                finding.severity,
                finding.matched_at,
                finding.description,
            ]


async def _iter_endpoint_rows(
    db: AsyncSession, records: list[IP]
) -> AsyncIterable[list[Any]]:
    for record in records:
        ip_address = str(record.ip_address)
        web_techs = await crud.get_web_techs_by_ip(db, record.id)
        for tech in web_techs:
            for endpoint in tech.endpoints:
                yield [
                    ip_address,
                    endpoint.path,
                    endpoint.method,
                    endpoint.source or "",
                ]


async def _export_csv(
    db: AsyncSession,
    target: str,
    header: list[str],
    rows: Any,
    suffix: str,
) -> StreamingResponse:
    """Resolve the target and stream one flat-entity table as CSV."""
    records, normalized, _ = await _target_ip_records(db, target)
    filename = f"nodeargus_{_safe_filename(normalized)}_{suffix}.csv"
    data = rows(db, records)
    return StreamingResponse(
        _csv_chunks(header, data),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{target}/ports")
async def export_ports(
    target: str, db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    """Export a flat table of discovered ports as CSV."""
    return await _export_csv(
        db,
        target,
        ["IP", "Port", "State", "Service", "Banner"],
        _iter_port_rows,
        "ports",
    )


@router.get("/{target}/vulns")
async def export_vulns(
    target: str, db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    """Export a flat table of Nuclei findings as CSV."""
    return await _export_csv(
        db,
        target,
        ["Target", "CVE/Template ID", "Severity", "Matched At", "Description"],
        _iter_vuln_rows,
        "vulns",
    )


@router.get("/{target}/endpoints")
async def export_endpoints(
    target: str, db: AsyncSession = Depends(get_db)
) -> StreamingResponse:
    """Export a flat table of katana-discovered endpoints as CSV."""
    return await _export_csv(
        db,
        target,
        ["Target", "URL", "Method", "Source"],
        _iter_endpoint_rows,
        "endpoints",
    )
