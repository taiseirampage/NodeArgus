from typing import Literal

from pydantic import BaseModel, Field, model_validator
from fastapi.encoders import jsonable_encoder

from app.scanner.validator import validate_domain, validate_target

ReconTool = Literal["subfinder", "amass"]
ScanType = Literal["recon", "active", "full", "amass"]
AmassMode = Literal["passive", "active"]

_TASK_NAME = "run_unified_recon_task"
_KNOWN_TOOLS: set[str] = {"subfinder", "amass"}


class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = "active"
    recon_tools: list[ReconTool] = Field(default_factory=lambda: ["subfinder"])
    amass_mode: AmassMode = "passive"

    @model_validator(mode="after")
    def normalize_target(self) -> "ScanRequest":
        if self.scan_type == "active":
            # IP/CIDR targets ignore recon_tools entirely.
            self.target = validate_target(self.target)
            self.recon_tools = []
            return self

        # recon / full / amass operate on a root FQDN.
        self.target = validate_domain(self.target)
        if self.scan_type == "amass":
            self.recon_tools = ["amass"]
            return self

        tools = [tool for tool in self.recon_tools if tool in _KNOWN_TOOLS]
        if not tools:
            raise ValueError(
                "recon_tools must contain at least one of: subfinder, amass"
            )
        self.recon_tools = tools
        return self


class ScanResponse(BaseModel):
    task_id: str
    status: str
    scan_type: ScanType = "active"
    recon_tools: list[ReconTool] = Field(default_factory=lambda: ["subfinder"])


class ScanStatusResponse(BaseModel):
    task_id: str
    status: str
    result: dict[str, object] | None = None
    error: str | None = None
    progress: dict[str, object] | None = None


def result_payload(value: object) -> dict[str, object] | None:
    """Convert a Celery result into a JSON-compatible response dictionary."""
    if value is None:
        return None
    encoded = jsonable_encoder(value)
    if isinstance(encoded, dict):
        return {str(key): item for key, item in encoded.items()}
    return {"value": encoded}
