from typing import Literal

from pydantic import BaseModel, ConfigDict


class GraphNode(BaseModel):
    """A node displayed in the network graph."""

    id: str
    ip: str
    node_type: Literal["ip", "domain", "subdomain", "asn"] = "ip"
    source: str | None = None
    resolved_ips: list[str] = []
    country: str | None = None
    city: str | None = None
    os: str | None = None
    ports_count: int
    is_traceroute_hop: bool = False
    traceroute_hop: int | None = None
    traceroute_rtt: str | None = None
    asn_number: str | None = None
    asn_cidr: str | None = None
    asn_org: str | None = None


class GraphLink(BaseModel):
    """A typed relationship between two graph nodes."""

    source: str
    target: str
    type: str


class GraphResponse(BaseModel):
    """Graph data for one center IP and its immediate relationships."""

    center_ip: str
    nodes: list[GraphNode]
    links: list[GraphLink]

    model_config = ConfigDict(from_attributes=True)
