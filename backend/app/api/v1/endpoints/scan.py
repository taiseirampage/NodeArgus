import logging

from fastapi import APIRouter, status
from celery.result import AsyncResult

from app.celery_worker import celery_app
from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanStatusResponse,
    result_payload,
)
from app.tasks import run_scan_task
from app.tasks.amass_recon import run_amass_task
from app.tasks.pipeline import run_full_scan_task
from app.tasks.recon import run_unified_recon_task


router = APIRouter()
logger = logging.getLogger(__name__)


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
    if request.scan_type == "active":
        task = run_scan_task.delay(request.target)
    elif request.scan_type == "full":
        task = run_full_scan_task.delay(
            request.target, request.recon_tools, request.amass_mode
        )
    elif request.scan_type == "amass":
        task = run_amass_task.delay(request.target, request.amass_mode)
    else:
        task = run_unified_recon_task.delay(
            request.target, request.recon_tools, request.amass_mode
        )
    return ScanResponse(
        task_id=task.id,
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
