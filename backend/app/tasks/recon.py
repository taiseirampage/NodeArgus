import asyncio
import ipaddress
import logging
import socket
from typing import Any

from celery import Task

from app.celery_worker import celery_app
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.scanner.subfinder_wrapper import SubfinderError, run_subfinder
from app.scanner.validator import validate_domain

from app.tasks.scan import _run_async


logger = logging.getLogger(__name__)

_RESOLVE_CONCURRENCY = 16


def _record_fields(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract the hostname and passive source from a Subfinder record."""
    host = record.get("host")
    if not isinstance(host, str) or not host.strip():
        host = record.get("name")
    host = str(host).strip().rstrip(".").lower() if isinstance(host, str) else host
    source = record.get("source")
    if not isinstance(source, str):
        source = None
    return host, source


async def _resolve_host(host: str, semaphore: asyncio.Semaphore) -> list[str]:
    """Resolve a hostname to a list of valid IP addresses, deduplicated."""
    resolved: list[str] = []
    seen: set[str] = set()
    async with semaphore:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC
            )
        except (OSError, asyncio.TimeoutError, socket.gaierror):
            return resolved
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        raw = sockaddr[0]
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            resolved.append(ip)
    return resolved


async def _resolve_batches(
    hosts: list[str], batch_size: int = 50
) -> dict[str, list[str]]:
    """Resolve hostnames to IPs in bounded batches to limit DNS fan-out."""
    mapping: dict[str, list[str]] = {}
    semaphore = asyncio.Semaphore(_RESOLVE_CONCURRENCY)
    for start in range(0, len(hosts), batch_size):
        chunk = hosts[start : start + batch_size]
        results = await asyncio.gather(
            *(_resolve_host(host, semaphore) for host in chunk)
        )
        mapping.update(zip(chunk, results))
    return mapping


async def _enrich_with_ips(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach resolved IPs to each unique subdomain record."""
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        host, source = _record_fields(record)
        if not host:
            continue
        existing = unique.get(host)
        if existing is None:
            unique[host] = {"name": host, "source": source}
            continue
        if existing.get("source") is None and source is not None:
            existing["source"] = source

    ips_by_host = await _resolve_batches(list(unique.keys()))
    enriched: list[dict[str, Any]] = []
    for host, entry in unique.items():
        entry["ip_addresses"] = ips_by_host.get(host, [])
        enriched.append(entry)
    return enriched


async def _run_recon(target: str) -> dict[str, Any]:
    """Run Subfinder and persist the discovered domains, subdomains, and IPs."""
    domain = validate_domain(target)
    logger.info("Starting passive recon for %s", domain)
    subfinder_records = await run_subfinder(domain)
    if not subfinder_records:
        logger.info("No subdomains found for %s", domain)
        return {"domain": domain, "subdomains": 0, "links": 0}

    enriched = await _enrich_with_ips(subfinder_records)
    async with AsyncSessionLocal() as db:
        saved_counts = await crud.save_recon_results(db, domain, enriched)
    counts: dict[str, Any] = {
        "domains": saved_counts["domains"],
        "subdomains": saved_counts["subdomains"],
        "links": saved_counts["links"],
    }
    counts["domain"] = domain
    logger.info(
        "Recon task finished for %s: found %d, saved %d",
        domain,
        len(enriched),
        counts["subdomains"],
    )
    return counts


@celery_app.task(name="run_recon_task", bind=True)
def run_recon_task(self: Task, target: str) -> dict[str, Any]:
    """Enumerate subdomains passively with Subfinder and persist them."""
    try:
        return _run_async(_run_recon(target))
    except (SubfinderError, ValueError) as error:
        logger.exception("Recon task failed for target %s", target)
        self.update_state(state="FAILURE", meta={"error": str(error)})
        raise
