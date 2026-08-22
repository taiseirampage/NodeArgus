import ipaddress
import logging
from collections.abc import Mapping

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import VulnScanResponse, VulnerabilityResponse
from app.celery_worker import celery_app
from app.config import settings
from app.db import crud
from app.db.database import get_db
from app.scanner.nuclei_wrapper import (
    validate_proxy,
    validate_tags,
    validate_user_agent,
)
from app.scanner.validator import validate_target
from app.tasks import run_vuln_scan_task, run_web_host_vuln_scan_task


router = APIRouter()
logger = logging.getLogger(__name__)


def _validate_ip(value: str) -> str:
    normalized = validate_target(value)
    if "," in normalized or "/" in normalized:
        raise ValueError("a single IP address is required")
    return str(ipaddress.ip_address(normalized))


async def _get_ip_or_404(ip: str, db: AsyncSession) -> tuple[str, int]:
    try:
        normalized_ip = _validate_ip(ip)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ip must be a valid single IP address",
        ) from error
    record = await crud.get_ip_by_address(db, normalized_ip)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP not found in database",
        )
    return normalized_ip, record.id


def _vulnerability_response(value: object) -> VulnerabilityResponse:
    return VulnerabilityResponse.model_validate(value, from_attributes=True)


@router.post(
    "/{ip}/web", status_code=status.HTTP_202_ACCEPTED, response_model=VulnScanResponse
)
async def create_web_host_vulnerability_scan(
    ip: str,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
    proxy: str | None = None,
    user_agent: str | None = None,
    use_stealth_mode: bool = False,
    waf_bypass_mode: bool = False,
    tags: list[str] | None = None,
) -> VulnScanResponse:
    """Queue a Nuclei scan against the IP's discovered web hosts.

    Scanning the bare IP misses findings on shared/virtual-host hosting where
    the site only answers for its hostname. This endpoint probes every WebTech
    URL recorded for the IP, so Nuclei sees the correct virtual host. Findings
    are stored under the IP node and surfaced by the usual status endpoints.

    Args:
        ip: A single validated IP address known to NodeArgus.
        force: When False, reuse the 24-hour cached results.
        proxy: Optional HTTP(S)/SOCKS5 proxy URL.
        user_agent: Optional custom User-Agent header.
        use_stealth_mode: Slow the scan down to avoid WAF detection.
        waf_bypass_mode: Aggressive WAF bypass flags/headers.
        tags: Optional Nuclei template tags (repeated query param, e.g.
            ``?tags=wordpress&tags=cve``) to widen or narrow coverage.

    Returns:
        A VulnScanResponse describing the queued web-host scan task.
    """
    normalized_ip, ip_id = await _get_ip_or_404(ip, db)
    web_techs = await crud.get_web_techs_by_ip(db, ip_id)
    if not web_techs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No web hosts recorded for this IP; run web recon first",
        )
    if waf_bypass_mode and use_stealth_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WAF Bypass Mode and Stealth Mode are mutually exclusive; "
            "enable only one of them",
        )
    if waf_bypass_mode and not settings.ALLOW_WAF_BYPASS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="WAF Bypass Mode is disabled; set ALLOW_WAF_BYPASS=true in "
            ".env to enable it",
        )
    try:
        validated_proxy = validate_proxy(proxy) if proxy else None
        validated_user_agent = validate_user_agent(user_agent) if user_agent else None
        validated_tags = validate_tags(tags)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    task_options: dict[str, object] = {}
    if validated_proxy is not None:
        task_options["proxy"] = validated_proxy
    if validated_user_agent is not None:
        task_options["user_agent"] = validated_user_agent
    if validated_tags is not None:
        task_options["tags"] = [validated_tags]
    if use_stealth_mode:
        task_options["use_stealth_mode"] = True
    if waf_bypass_mode:
        task_options["waf_bypass_mode"] = True
    task = run_web_host_vuln_scan_task.delay(normalized_ip, force, **task_options)
    return VulnScanResponse(task_id=task.id, status="queued")


@router.post(
    "/{ip}", status_code=status.HTTP_202_ACCEPTED, response_model=VulnScanResponse
)
async def create_vulnerability_scan(
    ip: str,
    force: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    proxy: str | None = None,
    user_agent: str | None = None,
    use_stealth_mode: bool = False,
    waf_bypass_mode: bool = False,
) -> VulnScanResponse:
    """Queue a Nuclei scan for an IP already known to NodeArgus."""
    normalized_ip, _ = await _get_ip_or_404(ip, db)
    if waf_bypass_mode and use_stealth_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="WAF Bypass Mode and Stealth Mode are mutually exclusive; "
            "enable only one of them",
        )
    if waf_bypass_mode and not settings.ALLOW_WAF_BYPASS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="WAF Bypass Mode is disabled; set ALLOW_WAF_BYPASS=true in "
            ".env to enable it",
        )
    try:
        validated_proxy = validate_proxy(proxy) if proxy else None
        validated_user_agent = validate_user_agent(user_agent) if user_agent else None
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    task_options: dict[str, object] = {}
    if validated_proxy is not None:
        task_options["proxy"] = validated_proxy
    if validated_user_agent is not None:
        task_options["user_agent"] = validated_user_agent
    if use_stealth_mode:
        task_options["use_stealth_mode"] = True
    if waf_bypass_mode:
        task_options["waf_bypass_mode"] = True
    task = run_vuln_scan_task.delay(normalized_ip, force, **task_options)
    return VulnScanResponse(task_id=task.id, status="queued")


@router.get("/{ip}/latest", response_model=VulnScanResponse)
async def get_latest_vulnerabilities(
    ip: str, db: AsyncSession = Depends(get_db)
) -> VulnScanResponse:
    """Return the latest persisted vulnerability findings without scanning."""
    _, ip_id = await _get_ip_or_404(ip, db)
    findings = await crud.get_vulnerabilities_by_ip(db, ip_id)
    return VulnScanResponse(
        status="cached" if findings else "success",
        vulnerabilities=[_vulnerability_response(item) for item in findings],
        message="Results from cache" if findings else None,
    )


@router.post("/{ip}/{task_id}/cancel", response_model=VulnScanResponse)
async def cancel_vulnerability_scan(
    ip: str, task_id: str, db: AsyncSession = Depends(get_db)
) -> VulnScanResponse:
    """Revoke a running vulnerability scan and terminate its worker process."""
    await _get_ip_or_404(ip, db)
    task = AsyncResult(task_id, app=celery_app)
    if task.state == "SUCCESS":
        return VulnScanResponse(task_id=task_id, status="success")
    if task.state == "FAILURE":
        return VulnScanResponse(
            task_id=task_id, status="failed", message="Task already failed"
        )
    if task.state == "REVOKED":
        return VulnScanResponse(
            task_id=task_id, status="cancelled", message="Scan already cancelled"
        )
    task.revoke(terminate=True, signal="SIGTERM")
    logger.info("Cancelled vulnerability scan task %s", task_id)
    return VulnScanResponse(
        task_id=task_id, status="cancelled", message="Vulnerability scan cancelled"
    )


@router.get("/{ip}/{task_id}", response_model=VulnScanResponse)
async def get_vulnerability_scan_status(
    ip: str, task_id: str, db: AsyncSession = Depends(get_db)
) -> VulnScanResponse:
    """Return Celery state and database-backed findings for a vulnerability scan."""
    _, ip_id = await _get_ip_or_404(ip, db)
    try:
        task = AsyncResult(task_id, app=celery_app)
        if task.state == "PENDING":
            return VulnScanResponse(task_id=task_id, status="processing")
        if task.state == "FAILURE":
            info = task.info
            error = info.get("error", info) if isinstance(info, Mapping) else info
            return VulnScanResponse(
                task_id=task_id, status="failed", message=str(error)
            )
        if task.state == "REVOKED":
            return VulnScanResponse(
                task_id=task_id,
                status="cancelled",
                message="Vulnerability scan cancelled",
            )
        if task.state == "SUCCESS":
            findings = await crud.get_vulnerabilities_by_ip(db, ip_id)
            task_result = task.result if isinstance(task.result, dict) else {}
            result_status = task_result.get("status", "success")
            if result_status not in {"success", "cached"}:
                result_status = "success"
            return VulnScanResponse(
                task_id=task_id,
                status=result_status,
                vulnerabilities=[_vulnerability_response(item) for item in findings],
                message=task_result.get("message"),
            )
        return VulnScanResponse(task_id=task_id, status="processing")
    except Exception as error:
        logger.exception("Unable to read vulnerability task %s", task_id)
        return VulnScanResponse(
            task_id=task_id,
            status="failed",
            message=f"Unable to read task status: {error}",
        )
