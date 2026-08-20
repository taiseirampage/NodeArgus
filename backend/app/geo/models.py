from pydantic import BaseModel


class GeoLocation(BaseModel):
    """Geographic and network metadata for an IP address."""

    ip: str
    country: str = ""
    country_code: str = ""
    city: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    isp: str = ""

    model_config = {"extra": "forbid"}
