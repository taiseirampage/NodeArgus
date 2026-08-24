from typing import Literal

from pydantic import BaseModel, Field, model_validator
from fastapi.encoders import jsonable_encoder

from app.scanner.validator import validate_domain, validate_target

ReconTool = Literal["subfinder", "amass"]
ScanType = Literal["recon", "active", "full", "amass"]
AmassMode = Literal["passive", "active"]

_TASK_NAME = "run_unified_recon_task"
_KNOWN_TOOLS: set[str] = {"subfinder", "amass"}


def _split_targets(target: str) -> list[str]:
    """Split a comma-separated target string into non-empty trimmed items."""
    return [item.strip() for item in target.split(",") if item.strip()]


class ScanRequest(BaseModel):
    target: str
    scan_type: ScanType = "active"
    recon_tools: list[ReconTool] = Field(default_factory=lambda: ["subfinder"])
    amass_mode: AmassMode = "passive"

    def get_targets(self) -> list[str]:
        """Split, trim, and validate the comma-separated target list.

        An ``active`` scan treats every element as an IP or CIDR and validates
        the whole list with ``validate_target``. ``recon``/``full``/``amass``
        scans treat every element as a root FQDN and validate each one with
        ``validate_domain``. Validation is fail-fast: the first invalid element
        raises ``ValueError`` naming the offending item, which FastAPI turns
        into a 422 response.
        """
        items = _split_targets(self.target)
        if not items:
            raise ValueError("target must contain at least one IP, CIDR, or domain")
        if self.scan_type == "active":
            return [
                item.strip() for item in validate_target(",".join(items)).split(",")
            ]
        validated: list[str] = []
        for item in items:
            try:
                validated.append(validate_domain(item))
            except ValueError as error:
                raise ValueError(f"invalid domain '{item}': {error}") from error
        return validated

    @model_validator(mode="after")
    def normalize_target(self) -> "ScanRequest":
        if self.scan_type == "active":
            # IP/CIDR targets ignore recon_tools entirely.
            self.target = validate_target(self.target)
            self.recon_tools = []
            return self

        # recon / full / amass operate on one or more root FQDNs.
        self.get_targets()
        if self.scan_type == "amass":
            self.recon_tools = ["amass"]
            return self

        tools: list[ReconTool] = [
            tool for tool in self.recon_tools if tool in _KNOWN_TOOLS
        ]
        if not tools:
            raise ValueError(
                "recon_tools must contain at least one of: subfinder, amass"
            )
        self.recon_tools = tools
        return self


class ScanResponse(BaseModel):
    task_id: str
    task_ids: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
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
