import asyncio
import logging
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from celery import Task

from app.config import settings
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.geo.geoip import GeoIPService
from app.geo.models import GeoLocation
from app.scanner.models import NmapResult, NmapService, ScannedPort

from .celery_worker import celery_app
from .scanner.masscan_wrapper import run_masscan
from .scanner.nmap_wrapper import run_nmap
from .scanner.validator import validate_target


logger = logging.getLogger(__name__)
_AsyncResult = TypeVar("_AsyncResult")
_worker_loop: asyncio.AbstractEventLoop | None = None
_worker_loop_lock = threading.Lock()


async def _save_scan_result(result: NmapResult, geo: GeoLocation) -> None:
    """Persist a scan result using one async database session."""
    async with AsyncSessionLocal() as db:
        await crud.save_scan_result(db=db, result=result, geo=geo)


def _masscan_services(ports: list[ScannedPort]) -> list[NmapService]:
    return [
        NmapService(
            port=port.port,
            protocol=port.protocol,
            service=port.service or "unknown",
            version=port.version,
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
                            os_detection="",
                            scan_time=0.0,
                        )
                else:
                    nmap_result = NmapResult(
                        target=single_target,
                        services=[],
                        os_detection="",
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
        self.update_state(state="FAILURE", meta={"error": str(error)})
        raise
