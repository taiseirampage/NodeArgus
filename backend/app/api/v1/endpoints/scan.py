import logging
from collections.abc import Mapping

from fastapi import APIRouter, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, field_validator
from celery.result import AsyncResult

from app.celery_worker import celery_app
from app.tasks import run_scan_task
from app.scanner.validator import validate_target as validate_scan_target


router = APIRouter()
logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        try:
            return validate_scan_target(value)
        except ValueError as error:
            raise ValueError(str(error)) from error


class ScanResponse(BaseModel):
    task_id: str
    status: str


class ScanStatusResponse(BaseModel):
    task_id: str
    status: str
    result: dict[str, object] | None = None
    error: str | None = None


def _result_payload(value: object) -> dict[str, object] | None:
    """Convert a Celery result into a JSON-compatible response dictionary."""
    if value is None:
        return None
    encoded = jsonable_encoder(value)
    if isinstance(encoded, Mapping):
        return {str(key): item for key, item in encoded.items()}
    return {"value": encoded}


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED, response_model=ScanResponse)
async def create_scan(request: ScanRequest) -> ScanResponse:
    task = run_scan_task.delay(request.target)
    return ScanResponse(task_id=task.id, status="queued")


@router.get("/scan/{task_id}", response_model=ScanStatusResponse)
def get_scan_status(task_id: str) -> ScanStatusResponse:
    """Return the current state and stored result of a Celery scan task."""
    try:
        task = AsyncResult(task_id, app=celery_app)
        state = task.state
        if state == "PENDING":
            return ScanStatusResponse(task_id=task_id, status="pending")
        if state == "SUCCESS":
            return ScanStatusResponse(
                task_id=task_id,
                status="success",
                result=_result_payload(task.result),
            )
        if state == "FAILURE":
            info = task.info
            error = info.get("error", info) if isinstance(info, dict) else info
            return ScanStatusResponse(
                task_id=task_id,
                status="failed",
                error=str(error),
            )
        return ScanStatusResponse(task_id=task_id, status=state.lower())
    except Exception as error:
        logger.exception("Unable to read Celery task status for %s", task_id)
        return ScanStatusResponse(
            task_id=task_id,
            status="failed",
            error=f"Unable to read task status: {error}",
        )
