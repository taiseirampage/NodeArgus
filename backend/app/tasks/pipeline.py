import asyncio
import logging
from typing import Any

from celery import Task, chord, group

from app.celery_worker import celery_app
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.scanner.validator import validate_domain

from .recon import run_unified_recon_task
from .scan import _run_async, run_active_scan_task
from .web_recon import WEB_PORTS, run_web_recon_task


logger = logging.getLogger(__name__)


async def _collect_domain_ips(domain: str) -> list[str]:
    """Return the unique IPs attached to a domain's discovered subdomains."""
    async with AsyncSessionLocal() as db:
        return await crud.get_domain_ips(db, domain)


async def _collect_web_recon_ips(domain: str) -> list[str]:
    """Return resolved IPs of a domain that have an open web port.

    This runs after the active-scan phase so Nmap results are already in the
    database. It is the gate that keeps httpx/katana off arbitrary addresses.
    """
    async with AsyncSessionLocal() as db:
        ips = await crud.get_domain_ips(db, domain)
        return await crud.get_ips_with_web_ports(db, ips, WEB_PORTS)


def _group_active_scans(ips: list[str]) -> Any:
    """Build a Celery group that scans each IP concurrently across workers."""
    return group(run_active_scan_task.s(ip) for ip in ips)


@celery_app.task(name="dispatch_web_recon_task")
def dispatch_web_recon_task(active_results: Any, domain: str) -> dict[str, Any]:
    """Enqueue web recon for hosts that proved to serve web traffic.

    Runs as the chord callback once the active-scan group finishes. It re-reads
    open web ports from the database and dispatches one ``run_web_recon_task``
    per matching IP, plus a domain-level run that crawls discovered subdomains.

    Args:
        active_results: Ignored results of the active-scan chord header.
        domain: The validated root FQDN.

    Returns:
        A dict describing how many web-recon targets were enqueued.
    """
    try:
        web_ips = _run_async(_collect_web_recon_ips(domain))
        if not web_ips:
            logger.info("No open web ports for %s; web recon phase skipped", domain)
            return {"status": "success", "domain": domain, "web_recon_targets": 0}

        # Domain-level httpx/katana coverage is already dispatched by the recon
        # phase (run_unified_recon_task); here we only cover per-IP web ports so
        # targets are not probed twice.
        group(run_web_recon_task.s(ip) for ip in web_ips).apply_async()
        logger.info(
            "Dispatched web recon for %d IP(s) of %s",
            len(web_ips),
            domain,
        )
        return {
            "status": "success",
            "domain": domain,
            "web_recon_targets": len(web_ips),
        }
    except Exception as error:
        logger.exception("Web recon dispatch failed for domain %s", domain)
        raise


@celery_app.task(name="run_full_scan_task", bind=True)
def run_full_scan_task(
    self: Task,
    target: str,
    recon_tools: list[str] | None = None,
    amass_mode: str = "passive",
) -> dict[str, Any]:
    """Run unified recon for a domain, then actively scan every resolved IP.

    The pipeline first discovers subdomains with the selected recon tools
    (Subfinder and/or Amass) and persists them. It then reads the unique IP
    addresses attached to those subdomains from the database and dispatches an
    active scan (Masscan + Nmap) for each IP. The scans run as a Celery chord
    header; a callback then reads open web ports and enqueues the httpx/katana
    web recon phase for hosts that actually serve HTTP/HTTPS.

    Args:
        target: A validated root FQDN.
        recon_tools: Subset of ``["subfinder", "amass"]`` to use for recon.
        amass_mode: ``passive`` or ``active`` Amass mode.

    Returns:
        A dict summarizing the recon and the number of active scans enqueued.
    """
    try:
        domain = validate_domain(target)
        logger.info("Full scan pipeline started for %s", domain)

        recon_result: dict[str, Any] = run_unified_recon_task.run(
            domain, recon_tools or ["subfinder"], amass_mode
        )
        logger.info("Recon phase finished for %s: %s", domain, recon_result)

        ips = _run_async(_collect_domain_ips(domain))
        if not ips:
            logger.warning(
                "No resolved IPs found for %s; active scan phase skipped", domain
            )
            return {
                "status": "success",
                "domain": domain,
                "subdomains_found": recon_result.get("total_subdomains", 0),
                "ips_to_scan": 0,
                "message": "No subdomains resolved to IP addresses",
            }

        # chord(header)(body) already sends the chord and returns the body's
        # AsyncResult; calling .apply_async() on it would raise AttributeError.
        chord_body = chord(_group_active_scans(ips))(dispatch_web_recon_task.s(domain))
        logger.info(
            "Dispatched %d active scans for %s via chord %s",
            len(ips),
            domain,
            chord_body.id,
        )
        return {
            "status": "success",
            "domain": domain,
            "subdomains_found": recon_result.get("total_subdomains", 0),
            "ips_to_scan": len(ips),
        }
    except Exception as error:
        logger.exception("Full scan pipeline failed for target %s", target)
        raise
