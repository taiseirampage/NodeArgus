from collections.abc import Iterable
import ipaddress
from itertools import combinations

from fastapi import HTTPException, status
from sqlalchemy import cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.db.models import IP, Link, Port
from app.scanner.validator import validate_target

from .models import GraphLink, GraphNode, GraphResponse


Selector = (
    ipaddress.IPv4Address
    | ipaddress.IPv6Address
    | ipaddress.IPv4Network
    | ipaddress.IPv6Network
)


def _parse_selector(target: str) -> tuple[str, list[Selector]]:
    try:
        normalized = validate_target(target)
        selectors: list[Selector] = []
        for item in normalized.split(","):
            if "/" in item:
                selectors.append(ipaddress.ip_network(item, strict=False))
            else:
                selectors.append(ipaddress.ip_address(item))
        return normalized, selectors
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ip must be a valid IP, CIDR, or comma-separated target list",
        ) from error


def _postgres_conditions(selectors: list[Selector]) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = []
    for selector in selectors:
        if isinstance(selector, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            conditions.append(IP.ip_address == str(selector))
        else:
            subnet = cast(selector.with_prefixlen, INET)
            conditions.append(IP.ip_address.op("<<")(subnet))
    return conditions


def _record_matches(record: IP, selector: Selector) -> bool:
    address = ipaddress.ip_address(record.ip_address)
    if isinstance(selector, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return address == selector
    try:
        return address in selector
    except TypeError:
        return False


async def _fetch_ips(db: AsyncSession, selectors: list[Selector]) -> list[IP]:
    if db.get_bind().dialect.name == "postgresql":
        statement = select(IP).where(or_(*_postgres_conditions(selectors)))
        result = await db.execute(statement)
        return list(result.scalars().all())

    result = await db.execute(select(IP))
    return [
        record
        for record in result.scalars().all()
        if any(_record_matches(record, selector) for selector in selectors)
    ]


async def _get_explicit_links(
    db: AsyncSession, node_ids: Iterable[int]
) -> list[tuple[int, int, str]]:
    ids = list(node_ids)
    if not ids:
        return []
    statement = select(Link.source_ip_id, Link.target_ip_id, Link.link_type).where(
        or_(Link.source_ip_id.in_(ids), Link.target_ip_id.in_(ids))
    )
    result = await db.execute(statement)
    return [(row[0], row[1], row[2]) for row in result.all()]


async def _get_port_counts(db: AsyncSession, node_ids: Iterable[int]) -> dict[int, int]:
    ids = list(node_ids)
    if not ids:
        return {}
    statement = (
        select(Port.ip_id, func.count(Port.id))
        .where(Port.ip_id.in_(ids))
        .group_by(Port.ip_id)
    )
    result = await db.execute(statement)
    return {row[0]: int(row[1]) for row in result.all()}


async def _load_linked_records(
    db: AsyncSession,
    explicit_links: list[tuple[int, int, str]],
    records_by_id: dict[int, IP],
) -> list[int]:
    linked_ids = list(
        dict.fromkeys(
            record_id
            for source_id, target_id, _ in explicit_links
            for record_id in (source_id, target_id)
        )
    )
    missing_ids = set(linked_ids) - records_by_id.keys()
    if missing_ids:
        result = await db.execute(select(IP).where(IP.id.in_(missing_ids)))
        records_by_id.update({record.id: record for record in result.scalars().all()})
    return [record_id for record_id in linked_ids if record_id in records_by_id]


def _node_from_record(record: IP, port_counts: dict[int, int]) -> GraphNode:
    ip = str(record.ip_address)
    return GraphNode(
        id=ip,
        ip=ip,
        country=record.country,
        city=record.city,
        os=record.os,
        ports_count=port_counts.get(record.id, 0),
    )


def _subnet_links(
    selectors: list[Selector], selected: list[IP], candidates: list[IP]
) -> list[GraphLink]:
    links: list[GraphLink] = []
    seen: set[tuple[str, str]] = set()
    selected_by_ip = {str(record.ip_address): record for record in selected}
    for selector in selectors:
        if isinstance(selector, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            membership_selector: Selector = ipaddress.ip_network(
                f"{selector}/24", strict=False
            )
            members = [
                record
                for record in candidates
                if _record_matches(record, membership_selector)
            ]
            anchor = selected_by_ip.get(str(selector))
            pairs = (
                (anchor, member)
                for member in members
                if anchor and member.id != anchor.id
            )
        else:
            members = [
                record for record in candidates if _record_matches(record, selector)
            ]
            pairs = combinations(members, 2)
        for source, target in pairs:
            if source is None:
                continue
            source_ip, target_ip = sorted(
                (str(source.ip_address), str(target.ip_address))
            )
            pair = (source_ip, target_ip)
            if pair in seen:
                continue
            seen.add(pair)
            links.append(
                GraphLink(source=source_ip, target=target_ip, type="same_subnet")
            )
    return links


async def compute_graph(db: AsyncSession, target_ip: str) -> GraphResponse:
    """Compute a graph for one IP, CIDR, or comma-separated target list.

    PostgreSQL calculates subnet membership with the native ``inet << inet``
    operator. Subnet relationships are returned only in this response and are
    never stored in the ``links`` table.
    """
    normalized, selectors = _parse_selector(target_ip)
    selected = await _fetch_ips(db, selectors)
    if not selected:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP not found in database",
        )

    subnet_selectors: list[Selector] = []
    for selector in selectors:
        if isinstance(selector, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            subnet_selectors.append(
                ipaddress.ip_network(f"{selector}/24", strict=False)
            )
        else:
            subnet_selectors.append(selector)
    candidates = await _fetch_ips(db, subnet_selectors)
    records_by_id = {record.id: record for record in selected + candidates}
    node_ids = list(records_by_id)
    explicit_links = await _get_explicit_links(db, node_ids)
    linked_ids = await _load_linked_records(db, explicit_links, records_by_id)
    ordered_ids = node_ids + [
        record_id for record_id in linked_ids if record_id not in node_ids
    ]
    port_counts = await _get_port_counts(db, ordered_ids)
    nodes = [
        _node_from_record(records_by_id[record_id], port_counts)
        for record_id in ordered_ids
    ]
    links = _subnet_links(selectors, selected, candidates)
    links.extend(
        GraphLink(
            source=str(records_by_id[source_id].ip_address),
            target=str(records_by_id[target_id].ip_address),
            type=link_type,
        )
        for source_id, target_id, link_type in explicit_links
        if source_id in records_by_id and target_id in records_by_id
    )
    return GraphResponse(center_ip=normalized, nodes=nodes, links=links)
