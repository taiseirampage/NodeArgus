import ipaddress

from fastapi import APIRouter, status
from pydantic import BaseModel, field_validator


router = APIRouter()


class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        target = value.strip()
        if not target:
            raise ValueError("target must not be empty")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            try:
                ipaddress.ip_network(target, strict=False)
            except ValueError as error:
                raise ValueError("target must be a valid IP address or CIDR") from error
        return target


class ScanResponse(BaseModel):
    task_id: str
    status: str
    message: str


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED, response_model=ScanResponse)
async def create_scan(request: ScanRequest) -> ScanResponse:
    return ScanResponse(
        task_id="stub-123",
        status="queued",
        message="Scanning not implemented yet",
    )
