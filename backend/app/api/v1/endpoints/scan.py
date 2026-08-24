import logging

from fastapi import APIRouter, status
from celery import group
from celery.result import AsyncResult

from app.celery_worker import celery_app
from app.schemas.scan import (
    AmassMode,
    ReconTool,
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    ScanType,
    result_payload,
)
from app.tasks import run_scan_task
from app.tasks.amass_recon import run_amass_task
from app.tasks.pipeline import run_full_scan_task
from app.tasks.recon import run_unified_recon_task


router = APIRouter()
logger = logging.getLogger(__name__)


def _dispatch_domain_group(
    domains: list[str],
    scan_type: ScanType,
    recon_tools: list[ReconTool],
    amass_mode: AmassMode,
) -> list[str]:
    """Enqueue one recon task per domain and run them in parallel.

    Subfinder/Amass only accept a single FQDN per invocation, so the comma
    list is split here at the API layer and dispatched as a ``celery.canvas.group``.
    Each child task runs on its own worker; the endpoint returns the individual
    task ids so callers can poll each one independently.

    Args:
        domains: Validated root FQDNs to scan.
        scan_type: ``recon``, ``full``, or ``amass``.
        recon_tools: Subset of ``["subfinder", "amass"]`` (ignored by ``amass``).
        amass_mode: ``passive`` or ``active`` for Amass.

    Returns:
        The list of Celery task ids, one per domain.
    """
    if scan_type == "recon":
        signatures = [
            run_unified_recon_task.s(domain, recon_tools, amass_mode)
            for domain in domains
        ]
    elif scan_type == "full":
        signatures = [
            run_full_scan_task.s(domain, recon_tools, amass_mode) for domain in domains
        ]
    else:
        signatures = [run_amass_task.s(domain, amass_mode) for domain in domains]

    workflow = group(signatures)
    group_result = workflow.apply_async()
    return [child.id for child in group_result.results if child.id is not None]


def _task_progress(task: AsyncResult) -> dict[str, object] | None:
    """Return per-tool progress metadata from an in-flight recon task."""
    info = task.info if isinstance(task.info, dict) else None
    if not info:
        return None
    progress = info.get("progress")
    if not isinstance(progress, dict):
        return None
    return {str(key): item for key, item in progress.items()}


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED, response_model=ScanResponse)
async def create_scan(request: ScanRequest) -> ScanResponse:
    targets = request.get_targets()

    if request.scan_type == "active":
        # One Masscan+Nmap task handles the whole IP/CIDR list internally.
        task = run_scan_task.delay(",".join(targets))
        task_ids = [task.id]
    else:
        # Domain recon/full/amass: one task per domain, run as a parallel group.
        task_ids = _dispatch_domain_group(
            targets, request.scan_type, request.recon_tools, request.amass_mode
        )

    return ScanResponse(
        task_id=task_ids[0],
        task_ids=task_ids,
        targets=targets,
        status="queued",
        scan_type=request.scan_type,
        recon_tools=request.recon_tools,
    )


@router.get("/scan/{task_id}/status", response_model=ScanStatusResponse)
def get_scan_status(task_id: str) -> ScanStatusResponse:
    """Return the current state, stored result, and recon progress of a task."""
    try:
        task = AsyncResult(task_id, app=celery_app)
        state = task.state
        if state == "PENDING":
            return ScanStatusResponse(task_id=task_id, status="pending")
        if state == "SUCCESS":
            return ScanStatusResponse(
                task_id=task_id,
                status="success",
                result=result_payload(task.result),
            )
        if state == "FAILURE":
            info = task.info
            error = info.get("error", info) if isinstance(info, dict) else info
            return ScanStatusResponse(
                task_id=task_id,
                status="failed",
                error=str(error),
            )
        return ScanStatusResponse(
            task_id=task_id,
            status=state.lower(),
            progress=_task_progress(task),
        )
    except Exception as error:
        logger.exception("Unable to read Celery task status for %s", task_id)
        return ScanStatusResponse(
            task_id=task_id,
            status="failed",
            error=f"Unable to read task status: {error}",
        )


# Backwards-compatible aliases so existing callers of /scan/{task_id} still work.
@router.get("/scan/{task_id}", response_model=ScanStatusResponse)
def get_scan_status_legacy(task_id: str) -> ScanStatusResponse:
    return get_scan_status(task_id)
