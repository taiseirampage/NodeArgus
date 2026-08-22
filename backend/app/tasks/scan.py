import asyncio
import ipaddress
import logging
import time
import threading
from collections.abc import Coroutine
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

from celery import Task

from app.config import settings
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.geo.geoip import GeoIPService
from app.geo.models import GeoLocation
from app.scanner.models import NmapResult, NmapService, ScannedPort

from app.celery_worker import celery_app
from app.scanner.masscan_wrapper import run_masscan
from app.scanner.nmap_wrapper import run_nmap
from app.scanner.nuclei_wrapper import (
    NucleiResult,
    NucleiVulnerability,
    run_nuclei,
    validate_proxy,
    validate_tags,
    validate_user_agent,
)
from app.scanner.validator import validate_target


logger = logging.getLogger(__name__)
_AsyncResult = TypeVar("_AsyncResult")
_worker_loop: asyncio.AbstractEventLoop | None = None
_worker_loop_lock = threading.Lock()
WAF_BYPASS_TASK_TIMEOUT_SECONDS = 3600


async def _save_scan_result(result: NmapResult, geo: GeoLocation) -> None:
    """Persist a scan result using one async database session."""
    async with AsyncSessionLocal() as db:
        record = await crud.save_scan_result(db=db, result=result, geo=geo)
        if result.traceroute:
            await crud.save_traceroute_hops(
                db,
                str(record.ip_address),
                [hop.model_dump() for hop in result.traceroute],
            )


def _masscan_services(ports: list[ScannedPort]) -> list[NmapService]:
    return [
        NmapService(
            port=port.port,
            protocol=port.protocol,
            service=port.service or "unknown",
            version=port.version,
            state="open",
        )
        for port in ports
    ]


def _merge_services(
    nmap_result: NmapResult, masscan_ports: list[ScannedPort]
) -> list[NmapService]:
    services = list(nmap_result.services)
    existing = {(service.port, service.protocol) for service in services}
    for service in _masscan_services(masscan_ports):
        if (service.port, service.protocol) not in existing:
            services.append(service)
    return services


def _run_async(coroutine: Coroutine[Any, Any, _AsyncResult]) -> _AsyncResult:
    """Run async persistence on one reusable event loop per Celery process.

    ``asyncio.run`` creates and closes a loop on every task. That invalidates
    asyncpg connections kept by SQLAlchemy's async pool for the next task.
    """
    global _worker_loop
    with _worker_loop_lock:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        _worker_loop = loop
        if loop.is_running():
            coroutine.close()
            raise RuntimeError("Celery task cannot run inside an active event loop")
        return loop.run_until_complete(coroutine)


def _vulnerability_payload(vulnerability: Any) -> dict[str, Any]:
    """Convert an ORM vulnerability into a JSON-safe Celery payload."""
    return {
        "id": vulnerability.id,
        "cve_id": vulnerability.cve_id,
        "name": vulnerability.name,
        "severity": vulnerability.severity,
        "description": vulnerability.description,
        "matched_at": vulnerability.matched_at,
        "found_at": vulnerability.found_at.isoformat(),
    }


async def _run_vulnerability_scan(
    target: str,
    force: bool,
    proxy: str | None,
    user_agent: str | None,
    use_stealth_mode: bool,
    waf_bypass_mode: bool,
) -> dict[str, Any]:
    """Check the database cache, scan when necessary, and persist findings."""
    async with AsyncSessionLocal() as db:
        record = await crud.get_ip_by_address(db, target)
        if record is None:
            raise ValueError("IP not found in database")
        last_scan = await crud.get_last_vuln_scan(db, record.id)
        now = datetime.now(timezone.utc)
        if last_scan is not None and last_scan.tzinfo is None:
            last_scan = last_scan.replace(tzinfo=timezone.utc)
        if (
            not force
            and last_scan is not None
            and now - last_scan.astimezone(timezone.utc) < timedelta(hours=24)
        ):
            cached = await crud.get_vulnerabilities_by_ip(db, record.id)
            logger.info("Using cached Nuclei results for %s", target)
            return {
                "status": "cached",
                "message": "Results from cache",
                "vulnerabilities": [_vulnerability_payload(item) for item in cached],
            }

        start_time = time.time()
        # No severity filter: Nuclei reports all severities (info/low/...).
        nuclei_options: dict[str, Any] = {}
        if proxy is not None:
            nuclei_options["proxy"] = proxy
        if user_agent is not None:
            nuclei_options["user_agent"] = user_agent
        if use_stealth_mode:
            nuclei_options["stealth_mode"] = True
        if waf_bypass_mode:
            nuclei_options["waf_bypass_mode"] = True
        nuclei_result: NucleiResult = run_nuclei(target, **nuclei_options)
        elapsed = time.time() - start_time
        logger.info(
            "Nuclei scan completed in %.2fs, found %d vulnerabilities",
            elapsed,
            len(nuclei_result.vulnerabilities),
        )
        await crud.save_vulnerabilities(db, record.id, nuclei_result.vulnerabilities)
        result: dict[str, Any] = {
            "status": "success",
            "vulnerabilities_count": len(nuclei_result.vulnerabilities),
        }
        if nuclei_result.timed_out:
            result["message"] = "Nuclei scan timed out; partial results saved"
        return result


@celery_app.task(name="run_vuln_scan_task", bind=True)
def run_vuln_scan_task(
    self: Task,
    target: str,
    force: bool = False,
    proxy: str | None = None,
    user_agent: str | None = None,
    use_stealth_mode: bool = False,
    waf_bypass_mode: bool = False,
) -> dict[str, Any]:
    """Run or reuse a 24-hour cached Nuclei vulnerability scan.

    ``waf_bypass_mode`` and ``use_stealth_mode`` are mutually exclusive because
    they push the scan in opposite directions: stealth mode slows the scan down
    to avoid detection, while WAF bypass mode accelerates it with aggressive
    concurrency and retries to get past Web Application Firewalls.
    """
    try:
        if waf_bypass_mode and use_stealth_mode:
            raise ValueError(
                "WAF Bypass Mode and Stealth Mode are mutually exclusive; "
                "enable only one of them"
            )
        if waf_bypass_mode and not settings.ALLOW_WAF_BYPASS:
            raise ValueError(
                "WAF Bypass Mode is disabled; set ALLOW_WAF_BYPASS=true in .env "
                "to enable it"
            )
        validated_target = validate_target(target)
        if "," in validated_target or "/" in validated_target:
            raise ValueError("vulnerability scans require one IP address")
        validated_target = str(ipaddress.ip_address(validated_target))
        validated_proxy = validate_proxy(proxy) if proxy else None
        validated_user_agent = validate_user_agent(user_agent) if user_agent else None
        if waf_bypass_mode:
            self.request.time_limit = WAF_BYPASS_TASK_TIMEOUT_SECONDS
            self.request.soft_time_limit = WAF_BYPASS_TASK_TIMEOUT_SECONDS
            logger.info(
                "[WAF BYPASS MODE] Starting aggressive scan for %s", validated_target
            )
        return _run_async(
            _run_vulnerability_scan(
                validated_target,
                force,
                validated_proxy,
                validated_user_agent,
                use_stealth_mode,
                waf_bypass_mode,
            )
        )
    except Exception as error:
        logger.exception("Vulnerability scan task failed for target %s", target)
        raise


async def _run_web_host_vulnerability_scan(
    target: str,
    force: bool,
    proxy: str | None,
    user_agent: str | None,
    use_stealth_mode: bool,
    waf_bypass_mode: bool,
    tags: str | None = None,
) -> dict[str, Any]:
    """Scan the discovered web hosts of one IP with Nuclei and persist them.

    Fetches the WebTech hosts recorded for the IP (from web recon) and runs one
    Nuclei pass per hostname URL so virtual-hosted sites are probed with the
    correct Host header. Findings are deduplicated and stored against the IP.

    Args:
        target: A single validated IP address.
        force: When False, reuse the 24-hour cache.
        proxy: Optional HTTP(S)/SOCKS5 proxy URL.
        user_agent: Optional custom User-Agent header.
        use_stealth_mode: Slow the scan down to avoid WAF detection.
        waf_bypass_mode: Enables aggressive WAF bypass flags/headers.

    Returns:
        A dict with the status and number of vulnerabilities saved.
    """
    async with AsyncSessionLocal() as db:
        record = await crud.get_ip_by_address(db, target)
        if record is None:
            raise ValueError("IP not found in database")
        now = datetime.now(timezone.utc)
        if not force:
            last_scan = await crud.get_last_vuln_scan(db, record.id)
            if last_scan is not None:
                if last_scan.tzinfo is None:
                    last_scan = last_scan.replace(tzinfo=timezone.utc)
                if now - last_scan.astimezone(timezone.utc) < timedelta(hours=24):
                    cached = await crud.get_vulnerabilities_by_ip(db, record.id)
                    logger.info("Using cached web-host results for %s", target)
                    return {
                        "status": "cached",
                        "message": "Results from cache",
                        "vulnerabilities": [
                            _vulnerability_payload(item) for item in cached
                        ],
                    }

        web_techs = await crud.get_web_techs_by_ip(db, record.id)
        hosts: list[str] = []
        seen: set[str] = set()
        for tech in web_techs:
            url = (tech.url or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            hosts.append(url)
        if not hosts:
            logger.info("No web hosts found for %s; skipping web-host scan", target)
            return {"status": "success", "vulnerabilities_count": 0}

        nuclei_options: dict[str, Any] = {}
        if proxy is not None:
            nuclei_options["proxy"] = proxy
        if user_agent is not None:
            nuclei_options["user_agent"] = user_agent
        if use_stealth_mode:
            nuclei_options["stealth_mode"] = True
        if waf_bypass_mode:
            nuclei_options["waf_bypass_mode"] = True
        if tags:
            nuclei_options["tags_filter"] = tags

        findings: list[Any] = []
        nuclei_vulnerabilities: list[NucleiVulnerability] = []
        timed_out = False
        start_time = time.time()
        for host in hosts:
            nuclei_result = run_nuclei(host, **nuclei_options)
            timed_out = timed_out or nuclei_result.timed_out
            nuclei_vulnerabilities.extend(nuclei_result.vulnerabilities)
            findings.extend(nuclei_result.vulnerabilities)
        elapsed = time.time() - start_time
        logger.info(
            "Web-host Nuclei scan for %s completed in %.2fs, hosts=%d vulns=%d",
            target,
            elapsed,
            len(hosts),
            len(findings),
        )
        await crud.save_vulnerabilities(db, record.id, nuclei_vulnerabilities)

        result: dict[str, Any] = {
            "status": "success",
            "target": target,
            "hosts_scanned": len(hosts),
            "vulnerabilities_count": len(findings),
        }
        if timed_out:
            result["message"] = "Nuclei timed out; partial results saved"
        return result


@celery_app.task(name="run_web_host_vuln_scan_task", bind=True)
def run_web_host_vuln_scan_task(
    self: Task,
    target: str,
    force: bool = False,
    proxy: str | None = None,
    user_agent: str | None = None,
    use_stealth_mode: bool = False,
    waf_bypass_mode: bool = False,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Run Nuclei against the web hosts of an IP.

    General-purpose ``-u http://<ip>`` scans fail on shared/virtual-host
    hosting because the server only answers for the correct Host header. This
    task reads the WebTech hosts recorded for the IP and scans each hostname URL
    instead, which is the only way Nuclei sees the actual vHost.

    Args:
        target: A single validated IP address.
        force: When False, reuse results cached in the last 24 hours.
        proxy: Optional HTTP(S)/SOCKS5 proxy URL.
        user_agent: Optional custom User-Agent header.
        use_stealth_mode: Slow the scan to avoid WAF detection.
        waf_bypass_mode: Aggressive WAF bypass flags/headers.
        tags: Optional Nuclei template tags (e.g. ``["wordpress", "cve"]``) to
            widen or narrow coverage; validated as safe tokens.

    Returns:
        A dict summarizing the number of vulnerabilities found.
    """
    try:
        if waf_bypass_mode and use_stealth_mode:
            raise ValueError(
                "WAF Bypass Mode and Stealth Mode are mutually exclusive; "
                "enable only one of them"
            )
        if waf_bypass_mode and not settings.ALLOW_WAF_BYPASS:
            raise ValueError(
                "WAF Bypass Mode is disabled; set ALLOW_WAF_BYPASS=true in .env "
                "to enable it"
            )
        validated_target = validate_target(target)
        if "," in validated_target or "/" in validated_target:
            raise ValueError("web-host vulnerability scans require one IP address")
        validated_target = str(ipaddress.ip_address(validated_target))
        validated_proxy = validate_proxy(proxy) if proxy else None
        validated_user_agent = validate_user_agent(user_agent) if user_agent else None
        validated_tags = validate_tags(tags)
        if waf_bypass_mode:
            self.request.time_limit = WAF_BYPASS_TASK_TIMEOUT_SECONDS
            self.request.soft_time_limit = WAF_BYPASS_TASK_TIMEOUT_SECONDS
        return _run_async(
            _run_web_host_vulnerability_scan(
                validated_target,
                force,
                validated_proxy,
                validated_user_agent,
                use_stealth_mode,
                waf_bypass_mode,
                validated_tags,
            )
        )
    except Exception as error:
        logger.exception("Web host vulnerability scan failed for target %s", target)
        raise


@celery_app.task(name="run_scan_task", bind=True)
def run_scan_task(self: Task, target: str) -> dict[str, int | str]:
    """Run scanners, enrich the result, and persist it in the database."""
    try:
        validated_target = validate_target(target)
        all_ports = 0
        with GeoIPService(settings.GEOIP_DB_PATH) as geo_service:
            for single_target in validated_target.split(","):
                masscan_result = run_masscan(single_target)
                logger.info("=== TASK: Masscan result received ===")
                logger.info(
                    "Masscan returned %d ports", len(masscan_result.scanned_ports)
                )
                logger.info("Ports data: %s", masscan_result.scanned_ports)
                port_spec = ",".join(
                    str(port.port) for port in masscan_result.scanned_ports
                )
                if port_spec:
                    try:
                        nmap_result = run_nmap(single_target, ports=port_spec)
                    except RuntimeError:
                        logger.exception("Nmap failed; keeping Masscan ports")
                        nmap_result = NmapResult(
                            target=single_target,
                            services=[],
                            os_detection="Unknown (Filtered)",
                            scan_time=0.0,
                        )
                else:
                    nmap_result = NmapResult(
                        target=single_target,
                        services=[],
                        os_detection="Unknown (Filtered)",
                        scan_time=0.0,
                    )
                logger.info("=== TASK: Nmap result received ===")
                logger.info("Nmap returned %d services", len(nmap_result.services))
                services = _merge_services(nmap_result, masscan_result.scanned_ports)
                all_ports += len(services)
                nmap_result = nmap_result.model_copy(update={"services": services})
                logger.info("=== TASK: Preparing to save to DB ===")
                logger.info("Total ports to save: %d", len(services))
                geo = geo_service.lookup(single_target)
                if geo is None:
                    geo = GeoLocation(ip=single_target)
                _run_async(_save_scan_result(nmap_result, geo))
                logger.info("=== TASK: Save completed ===")
        return {
            "status": "success",
            "ports_found": all_ports,
        }
    except Exception as error:
        logger.exception("Scan task failed for target %s", target)
        raise


@celery_app.task(name="run_active_scan_task", bind=True)
def run_active_scan_task(self: Task, target: str) -> dict[str, int | str]:
    """Active scan entrypoint used by the full-scan pipeline.

    The full-scan pipeline discovers subdomains first and then needs to scan
    every resolved IP. This task is the unit of work that the ``group`` of the
    pipeline dispatches in parallel across Celery workers; it reuses the same
    Masscan + Nmap flow as the standalone ``run_scan_task``.
    """
    logger.info("Active scan task started for %s", target)
    return run_scan_task.run(target)
