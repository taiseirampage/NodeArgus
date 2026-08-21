import logging
from typing import Any, Literal

from celery import Task

from app.celery_worker import celery_app
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.scanner.amass_wrapper import AmassError, run_amass
from app.scanner.validator import validate_domain

from app.tasks.scan import _run_async


logger = logging.getLogger(__name__)


async def _run_amass_recon(
    target: str, mode: Literal["passive", "active"]
) -> dict[str, Any]:
    """Run Amass against a validated domain and persist the results."""
    domain = validate_domain(target)
    logger.info("Starting Amass recon for %s in %s mode", domain, mode)
    result = await run_amass(domain, mode)
    if not result.get("subdomains") and not result.get("asn_info"):
        logger.warning("Amass returned no findings for %s", domain)
        return {
            "domain": domain,
            "subdomains": 0,
            "asn_records": 0,
            "ip_links": 0,
        }

    async with AsyncSessionLocal() as db:
        counts = await crud.save_amass_results(db, domain, result)

    summary: dict[str, Any] = {
        "domain": domain,
        "subdomains": counts["subdomains"],
        "ip_links": counts["ip_links"],
        "asn_records": counts["asn_records"],
    }
    logger.info("Amass recon finished for %s: %s", domain, summary)
    return summary


@celery_app.task(name="run_amass_task", bind=True)
def run_amass_task(
    self: Task, target: str, mode: Literal["passive", "active"] = "passive"
) -> dict[str, Any]:
    """Enumerate subdomains, ASN, and infrastructure with OWASP Amass."""
    if mode not in ("passive", "active"):
        raise ValueError("amass mode must be 'passive' or 'active'")
    try:
        return _run_async(_run_amass_recon(target, mode))
    except (AmassError, ValueError) as error:
        logger.exception("Amass recon task failed for target %s", target)
        raise
