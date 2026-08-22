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
    state: str = "unknown"


class NmapResult(BaseModel):
    """Normalized result returned by an Nmap scan."""

    target: str
    services: list[NmapService]
    os_detection: str = ""
    scan_time: float = Field(ge=0)
    geo: GeoLocation | None = None
    scripts_output: dict[str, str] = Field(default_factory=dict)
    traceroute: list["NmapHop"] = Field(default_factory=list)
    has_anonymous_access: bool = False


class NmapHop(BaseModel):
    """One hop from the Nmap traceroute output."""

    ttl: int = Field(ge=1)
    ip: str | None = None
    hostname: str | None = None
    rtt: str | None = None
