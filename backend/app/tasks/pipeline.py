import asyncio
import logging
from typing import Any

from celery import Task, group

from app.celery_worker import celery_app
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.scanner.validator import validate_domain

from .recon import run_unified_recon_task
from .scan import _run_async, run_active_scan_task


logger = logging.getLogger(__name__)


async def _collect_domain_ips(domain: str) -> list[str]:
    """Return the unique IPs attached to a domain's discovered subdomains."""
    async with AsyncSessionLocal() as db:
        return await crud.get_domain_ips(db, domain)


def _group_active_scans(ips: list[str]) -> Any:
    """Build a Celery group that scans each IP concurrently across workers."""
    return group(run_active_scan_task.s(ip) for ip in ips)


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
    active scan (Masscan + Nmap) for each IP. The scans run as a Celery
    ``group`` so every worker picks one IP and finishes in parallel instead of
    scanning sequentially.

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

        workflow = _group_active_scans(ips)
        result = workflow.apply_async()
        logger.info(
            "Dispatched %d active scans for %s via group %s",
            len(ips),
            domain,
            result.id,
        )
        return {
            "status": "success",
            "domain": domain,
            "subdomains_found": recon_result.get("total_subdomains", 0),
            "ips_to_scan": len(ips),
        }
    except Exception as error:
        logger.exception("Full scan pipeline failed for target %s", target)
        self.update_state(state="FAILURE", meta={"error": str(error)})
        raise
