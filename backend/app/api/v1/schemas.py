from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


Severity = Literal["critical", "high", "medium", "low", "info"]


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str | None
    name: str
    severity: Severity
    description: str
    matched_at: str
    found_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnScanResponse(BaseModel):
    task_id: str | None = None
    status: Literal["queued", "processing", "success", "failed", "cached", "cancelled"]
    vulnerabilities: list[VulnerabilityResponse] | None = None
    message: str | None = None
