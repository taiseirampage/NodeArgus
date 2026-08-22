from datetime import datetime
import ipaddress

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PortCreate(BaseModel):
    ip_id: int
    port_number: int = Field(ge=1, le=65535)
    protocol: str
    service: str
    banner: str | None = None
    state: str = "unknown"


class PortResponse(PortCreate):
    id: int

    model_config = ConfigDict(from_attributes=True)


class IPCreate(BaseModel):
    ip_address: str
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    provider: str | None = None
    os: str | None = None
    scripts_info: dict[str, str] | None = None
    has_anonymous_access: bool = False
    traceroute: list[dict[str, object]] | None = None
    last_scan: datetime | None = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as error:
            raise ValueError("ip_address must be a valid IP address") from error


class IPResponse(IPCreate):
    id: int
    created_at: datetime
    ports: list[PortResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class PortDetailsResponse(BaseModel):
    """Port data returned by the IP details endpoint."""

    port_number: int
    protocol: str
    service: str
    banner: str | None = None
    state: str = "unknown"

    model_config = ConfigDict(from_attributes=True)


class IPDetailsResponse(BaseModel):
    """Full IP details used by the node details panel."""

    ip: str
    country: str | None = None
    city: str | None = None
    os: str | None = None
    provider: str | None = None
    scripts_info: dict[str, str] = Field(default_factory=dict)
    has_anonymous_access: bool = False
    traceroute: list[dict[str, object]] = Field(default_factory=list)
    ports: list[PortDetailsResponse] = Field(default_factory=list)
    web_techs: list["WebTechResponse"] = Field(default_factory=list)


class EndpointResponse(BaseModel):
    """A crawled URL discovered on a web property."""

    id: int
    path: str
    method: str
    source: str | None = None
    discovered_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WebTechResponse(BaseModel):
    """A live web property discovered by httpx, with its crawled endpoints."""

    id: int
    url: str
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = Field(default_factory=list)
    web_server: str | None = None
    discovered_at: datetime
    endpoints: list[EndpointResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class LinkCreate(BaseModel):
    source_ip_id: int
    target_ip_id: int
    link_type: str

    @field_validator("link_type")
    @classmethod
    def reject_subnet_links(cls, value: str) -> str:
        if value == "same_subnet":
            raise ValueError("same_subnet links must be calculated dynamically")
        return value


class LinkResponse(LinkCreate):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityCreate(BaseModel):
    ip_id: int
    template_id: str
    cve_id: str | None = None
    name: str
    description: str
    severity: str
    matched_at: str


class VulnerabilityResponse(VulnerabilityCreate):
    id: int
    found_at: datetime

    model_config = ConfigDict(from_attributes=True)
