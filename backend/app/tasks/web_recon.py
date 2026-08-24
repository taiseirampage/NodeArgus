import asyncio
import ipaddress
import logging
import socket
from typing import Any, cast
from urllib.parse import urlsplit

from celery import Task

from app.celery_worker import celery_app
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.scanner.httpx_wrapper import HttpxError, run_httpx
from app.scanner.katana_wrapper import KatanaError, run_katana
from app.scanner.validator import validate_domain

from app.tasks.scan import _run_async


logger = logging.getLogger(__name__)

MAX_ENDPOINTS_PER_HOST = 500
MAX_KATANA_URLS = 50
# Ports treated as web services for pipeline/web-recon targeting.
WEB_PORTS = frozenset(
    {80, 443, 8080, 8443, 3000, 8000, 8888, 5000, 8001, 4000, 4200, 7000, 9000}
)
HTTPS_PORTS = frozenset({443, 8443})


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _origin_and_host(url: str) -> tuple[str, str]:
    """Return ``(scheme://netloc, hostname)`` for a URL, hostname fallback."""
    parsed = urlsplit(url)
    if parsed.scheme and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname or parsed.netloc
        return origin, host
    return url, url


async def _targets_for_ip(db: Any, ip: str) -> list[str]:
    """Build explicit http(s) URLs only from open web ports of one IP."""
    record = await crud.get_ip_by_address(db, ip)
    if record is None:
        return []
    ports = await crud.get_ports_by_ip(db, record.id)
    targets: list[str] = []
    for port in ports:
        if port.port_number not in WEB_PORTS:
            continue
        scheme = "https" if port.port_number in HTTPS_PORTS else "http"
        targets.append(f"{scheme}://{ip}:{port.port_number}")
    return targets


async def _targets_for_domain(db: Any, domain: str) -> list[str]:
    """Return the root domain plus all known subdomains as httpx targets."""
    names = [domain]
    route = await crud.get_domain_by_name(db, domain)
    if route is not None:
        subdomains = await crud.get_domain_subdomains(db, route.id)
        names.extend(sub.name for sub in subdomains)
    return list(dict.fromkeys(names))


async def _resolve_host_ip_id(db: Any, host: str) -> int | None:
    """Map a URL host to an IP record id, using DB data then DNS fallback."""
    host = host.rstrip(".")
    try:
        ip = str(ipaddress.ip_address(host))
        return await crud.get_or_create_ip_id(db, ip)
    except ValueError:
        pass

    db_ip_id = await crud.get_ip_id_by_hostname(db, host)
    if db_ip_id is not None:
        return db_ip_id

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, 80, type=socket.SOCK_STREAM
        )
    except socket.gaierror as error:
        logger.warning("DNS resolution failed for %s: %s", host, error)
        return None
    if not infos:
        return None
    resolved_ip = str(infos[0][4][0])
    return await crud.get_or_create_ip_id(db, resolved_ip)


async def _run_web_recon(
    target: str, max_endpoints_per_host: int = MAX_ENDPOINTS_PER_HOST
) -> dict[str, Any]:
    """Probe live web hosts with httpx, then crawl them with katana.

    httpx/katana are only ever pointed at hosts known to serve HTTP/HTTPS:
    either a validated domain plus its Subfinder/Amass subdomains, or an IP
    whose Nmap results show an open web port. This guard prevents spraying
    arbitrary addresses.

    Args:
        target: A single IP or a root domain.
        max_endpoints_per_host: Hard cap of endpoints persisted per web host.

    Returns:
        A dict with ``status``, target counts and saved ``web_techs``/
        ``endpoints`` (or ``skipped`` with a reason).
    """
    ip: str | None = None
    domain: str | None = None
    if _is_ip(target):
        ip = str(ipaddress.ip_address(target))
    else:
        domain = validate_domain(target)

    async with AsyncSessionLocal() as db:
        if ip is not None:
            targets = await _targets_for_ip(db, ip)
            if not targets:
                logger.info("No open web ports for %s; web recon skipped", ip)
                return {
                    "status": "skipped",
                    "reason": "no open web ports",
                    "target": ip,
                }
        else:
            targets = await _targets_for_domain(db, cast(str, domain))

        if not targets:
            return {
                "status": "skipped",
                "reason": "no web targets",
                "target": target,
            }

        try:
            httpx_records = await run_httpx(targets)
        except (HttpxError, ValueError) as error:
            logger.warning("httpx failed for %s: %s", target, error)
            return {
                "status": "failed",
                "reason": str(error),
                "target": target,
                "web_techs": 0,
                "endpoints": 0,
            }
        if not httpx_records:
            return {
                "status": "success",
                "web_techs": 0,
                "endpoints": 0,
                "target": target,
            }

        web_records: list[dict[str, Any]] = []
        for record in httpx_records:
            url = record.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            origin, host = _origin_and_host(url)
            ip_id = await _resolve_host_ip_id(db, host)
            if ip_id is None:
                logger.warning("Unable to map web host %s to an IP; skipping", host)
                continue
            web_records.append(
                {
                    "ip_id": ip_id,
                    "url": url,
                    "status_code": record.get("status_code"),
                    "title": record.get("title"),
                    "technologies": record.get("tech", []),
                    "web_server": record.get("web_server"),
                    "endpoints": [],
                }
            )

        crawl_urls = [
            item["url"] for item in web_records if item.get("status_code") == 200
        ][:MAX_KATANA_URLS]

        endpoints_by_origin: dict[str, list[dict[str, Any]]] = {}
        if crawl_urls:
            try:
                katana_records = await run_katana(crawl_urls)
            except (KatanaError, ValueError) as error:
                katana_records = []
                logger.warning(
                    "katana crawl failed for %s; keeping httpx results: %s",
                    target,
                    error,
                )
            for record in katana_records:
                endpoint = record.get("endpoint")
                if not isinstance(endpoint, str):
                    continue
                origin, _ = _origin_and_host(endpoint)
                endpoints_by_origin.setdefault(origin, []).append(
                    {
                        "path": endpoint,
                        "method": record.get("method") or "GET",
                        "source": record.get("source"),
                    }
                )

        for web_record in web_records:
            origin, _ = _origin_and_host(web_record["url"])
            endpoints = endpoints_by_origin.get(origin, [])
            web_record["endpoints"] = endpoints[:max_endpoints_per_host]

        summary = await crud.save_web_recon_result(db, web_records)
        logger.info("Web recon for %s: %s", target, summary)
        return {"status": "success", "target": target, **summary}


@celery_app.task(name="run_web_recon_task", bind=True)
def run_web_recon_task(
    self: Task,
    target: str,
    max_endpoints: int = MAX_ENDPOINTS_PER_HOST,
) -> dict[str, Any]:
    """Run httpx + katana web recon for one IP or root domain."""
    try:
        if _is_ip(target):
            validated_target = str(ipaddress.ip_address(target))
        else:
            validated_target = validate_domain(target)
        max_endpoints = int(max_endpoints)
        if max_endpoints <= 0:
            raise ValueError("max_endpoints must be a positive integer")
        return _run_async(_run_web_recon(validated_target, max_endpoints))
    except Exception as error:
        logger.exception("Web recon task failed for target %s", target)
        raise
