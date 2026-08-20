from pydantic import BaseModel, Field

from app.geo.models import GeoLocation


class ScannedPort(BaseModel):
    """An open port discovered by Masscan."""

    port: int = Field(ge=1, le=65535)
    protocol: str
    service: str
    version: str = ""


class MasscanResult(BaseModel):
    """Normalized result returned by a Masscan scan."""

    target: str
    scanned_ports: list[ScannedPort]
    scan_time: float = Field(ge=0)
    geo: GeoLocation | None = None


class NmapService(BaseModel):
    """A service discovered by Nmap."""

    port: int = Field(ge=1, le=65535)
    protocol: str
    service: str
    version: str
    os_match: str = ""


class NmapResult(BaseModel):
    """Normalized result returned by an Nmap scan."""

    target: str
    services: list[NmapService]
    os_detection: str
    scan_time: float = Field(ge=0)
    geo: GeoLocation | None = None
