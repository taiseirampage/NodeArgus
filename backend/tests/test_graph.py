from collections.abc import AsyncGenerator
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints.graph import get_graph
from app.db import crud
from app.db.models import Base, Domain, IP, Link, Port, Subdomain, subdomain_ip_link
from app.graph.compute import compute_domain_graph, compute_graph


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


async def add_ip(db: AsyncSession, address: str) -> IP:
    record = IP(ip_address=address)
    db.add(record)
    await db.flush()
    return record


@pytest.mark.asyncio
async def test_graph_returns_existing_center_and_port_count(
    db_session: AsyncSession,
) -> None:
    center = await add_ip(db_session, "192.168.1.10")
    db_session.add(
        Port(
            ip_id=center.id,
            port_number=443,
            protocol="tcp",
            service="https",
        )
    )
    await db_session.commit()

    response = await get_graph("192.168.1.10", db_session)

    assert response.center_ip == "192.168.1.10"
    assert response.nodes[0].id == "192.168.1.10"
    assert response.nodes[0].ports_count == 1
    assert response.links == []


@pytest.mark.asyncio
async def test_graph_returns_404_for_unknown_ip(db_session: AsyncSession) -> None:
    with pytest.raises(HTTPException) as error:
        await get_graph("192.168.1.10", db_session)

    assert error.value.status_code == 404
    assert error.value.detail == "IP not found in database"


@pytest.mark.asyncio
async def test_graph_computes_same_subnet_neighbors_without_links_rows(
    db_session: AsyncSession,
) -> None:
    center = await add_ip(db_session, "192.168.1.10")
    neighbor = await add_ip(db_session, "192.168.1.20")
    outside_subnet = await add_ip(db_session, "192.168.2.20")
    db_session.add(
        Port(
            ip_id=neighbor.id,
            port_number=22,
            protocol="tcp",
            service="ssh",
        )
    )
    await db_session.commit()

    response = await compute_graph(db_session, "192.168.1.10")

    assert {node.ip for node in response.nodes} == {
        "192.168.1.10",
        "192.168.1.20",
    }
    assert response.nodes[1].ports_count == 1
    assert [link.model_dump() for link in response.links] == [
        {
            "source": "192.168.1.10",
            "target": "192.168.1.20",
            "type": "same_subnet",
        }
    ]
    assert outside_subnet.id not in {node.id for node in response.nodes}


@pytest.mark.asyncio
async def test_graph_includes_explicit_links_and_linked_node(
    db_session: AsyncSession,
) -> None:
    center = await add_ip(db_session, "10.0.0.1")
    linked = await add_ip(db_session, "8.8.8.8")
    db_session.add(
        Link(
            source_ip_id=center.id,
            target_ip_id=linked.id,
            link_type="same_dns",
        )
    )
    await db_session.commit()

    response = await compute_graph(db_session, "10.0.0.1")

    assert {node.ip for node in response.nodes} == {"10.0.0.1", "8.8.8.8"}
    assert response.links[0].model_dump() == {
        "source": "10.0.0.1",
        "target": "8.8.8.8",
        "type": "same_dns",
    }


@pytest.mark.asyncio
async def test_graph_accepts_comma_separated_ip_list(
    db_session: AsyncSession,
) -> None:
    await add_ip(db_session, "192.168.1.10")
    await add_ip(db_session, "192.168.1.20")
    await add_ip(db_session, "192.168.1.100")
    await db_session.commit()

    response = await compute_graph(
        db_session, "192.168.1.10,192.168.1.20,192.168.1.100"
    )

    assert response.center_ip == "192.168.1.10,192.168.1.20,192.168.1.100"
    assert {node.ip for node in response.nodes} == {
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.100",
    }
    assert len(response.links) == 3
    assert response.links[0].type == "same_subnet"


@pytest.mark.asyncio
async def test_graph_accepts_cidr_target(db_session: AsyncSession) -> None:
    await add_ip(db_session, "192.168.1.10")
    await add_ip(db_session, "192.168.1.20")
    await db_session.commit()

    response = await compute_graph(db_session, "192.168.1.0/24")

    assert response.center_ip == "192.168.1.0/24"
    assert {node.ip for node in response.nodes} == {
        "192.168.1.10",
        "192.168.1.20",
    }
    assert len(response.links) == 1


@pytest.mark.asyncio
async def test_graph_includes_traceroute_chain_and_hop_metadata(
    db_session: AsyncSession,
) -> None:
    target = await add_ip(db_session, "203.0.113.10")
    await db_session.commit()

    hops = [
        {"hop": 1, "ip": "192.0.2.1", "rtt": "1.0"},
        {"hop": 2, "ip": "192.0.2.2", "rtt": "5.0"},
        {"hop": 3, "ip": "*", "rtt": "*"},
    ]
    await crud.save_traceroute_hops(db_session, str(target.ip_address), hops)
    await crud.save_traceroute_hops(db_session, str(target.ip_address), hops)

    response = await compute_graph(db_session, "203.0.113.10")

    hop_nodes = [node for node in response.nodes if node.is_traceroute_hop]
    assert {node.ip for node in hop_nodes} == {"192.0.2.1", "192.0.2.2"}
    assert [link.type for link in response.links] == [
        "traceroute_hop",
        "traceroute_hop",
    ]
    assert response.links[-1].target == "203.0.113.10"


@pytest.mark.asyncio
async def test_domain_graph_returns_domain_subdomain_and_ip_nodes(
    db_session: AsyncSession,
) -> None:
    domain = Domain(id=uuid4(), name="example.com")
    db_session.add(domain)
    await db_session.flush()
    subdomain = Subdomain(
        id=uuid4(), domain_id=domain.id, name="www.example.com", source="crtsh"
    )
    ip_record = IP(ip_address="1.2.3.4")
    db_session.add(ip_record)
    await db_session.flush()
    db_session.add(subdomain)
    await db_session.flush()
    await db_session.execute(
        subdomain_ip_link.insert().values(subdomain_id=subdomain.id, ip_id=ip_record.id)
    )
    await db_session.commit()

    response = await compute_domain_graph(db_session, "example.com")

    by_id = {node.id: node for node in response.nodes}
    assert set(by_id) == {"example.com", "www.example.com", "1.2.3.4"}
    assert by_id["example.com"].node_type == "domain"
    assert by_id["www.example.com"].node_type == "subdomain"
    assert by_id["www.example.com"].source == "crtsh"
    assert by_id["www.example.com"].resolved_ips == ["1.2.3.4"]
    assert by_id["1.2.3.4"].node_type == "ip"

    link_types = {(link.source, link.target, link.type) for link in response.links}
    assert ("example.com", "www.example.com", "subdomain_of") in link_types
    assert ("www.example.com", "1.2.3.4", "resolves_to") in link_types


@pytest.mark.asyncio
async def test_domain_graph_404_for_unknown_domain(db_session: AsyncSession) -> None:
    with pytest.raises(HTTPException) as error:
        await compute_domain_graph(db_session, "nonexistent.example")

    assert error.value.status_code == 404
    assert error.value.detail == "Domain not found in database"


@pytest.mark.asyncio
async def test_graph_dispatcher_handles_domain_and_ip_targets(
    db_session: AsyncSession,
) -> None:
    domain = Domain(id=uuid4(), name="example.com")
    db_session.add(domain)
    await db_session.flush()
    db_session.add(Subdomain(id=uuid4(), domain_id=domain.id, name="a.example.com"))
    await db_session.commit()

    domain_response = await get_graph("example.com", db_session)
    assert domain_response.center_ip == "example.com"

    with pytest.raises(HTTPException) as error:
        await get_graph("not a target!", db_session)
    assert error.value.status_code == 400
