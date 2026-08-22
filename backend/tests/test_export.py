import asyncio
import csv
import io
import json
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import HTTPException
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints.export import (
    export_endpoints,
    export_full_report,
    export_ports,
    export_vulns,
    _resolve_target,
)
from app.db import crud
from app.db.models import Base, Domain, Subdomain, subdomain_ip_link
from app.db.schemas import IPCreate, PortCreate
from app.scanner.nuclei_wrapper import NucleiVulnerability


@pytest_asyncio.fixture
async def export_database(
    tmp_path: Any,
) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'export.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    yield session_factory
    await engine.dispose()


async def _seed_ip(session_factory: async_sessionmaker[AsyncSession]) -> int:
    async with session_factory() as db:
        record = await crud.create_ip(db, IPCreate(ip_address="198.51.100.7"))
        await crud.create_port(
            db,
            PortCreate(
                ip_id=record.id,
                port_number=443,
                protocol="tcp",
                service="https",
                state="open",
            ),
        )
        findings = [
            NucleiVulnerability(
                template_id="test-template",
                cve_id="CVE-2026-0001",
                name="Test vulnerability",
                severity="high",
                description="A test finding",
                matched_at="https://example.com/",
                found_at=datetime.now(timezone.utc),
            )
        ]
        await crud.save_vulnerabilities(db, record.id, findings)
        await crud.save_web_recon_result(
            db,
            [
                {
                    "ip_id": record.id,
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Example",
                    "technologies": ["nginx"],
                    "web_server": "nginx",
                    "endpoints": [
                        {
                            "path": "https://example.com/admin",
                            "method": "GET",
                            "source": "https://example.com",
                        }
                    ],
                }
            ],
        )
        return record.id


@pytest.mark.asyncio
async def test_export_full_report_returns_nested_json(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    await _seed_ip(export_database)
    async with export_database() as db:
        response = await export_full_report("198.51.100.7", db)

    assert "attachment" in response.headers["Content-Disposition"]
    raw_body: Any = response.body
    if isinstance(raw_body, (bytes, bytearray)):
        raw_body = bytes(raw_body).decode("utf-8")
    payload = json.loads(raw_body)
    assert payload["target"] == "198.51.100.7"
    assert payload["target_type"] == "ip"
    assert payload["ips"][0]["ports"][0]["service"] == "https"
    assert payload["ips"][0]["vulnerabilities"][0]["cve_id"] == "CVE-2026-0001"
    assert payload["ips"][0]["web_techs"][0]["technologies"] == ["nginx"]
    assert payload["ips"][0]["web_techs"][0]["endpoints"][0]["url"] == (
        "https://example.com/admin"
    )


@pytest.mark.asyncio
async def test_export_full_report_404_for_missing_target(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    async with export_database() as db:
        with pytest.raises(HTTPException) as exc_info:
            await export_full_report("198.51.100.99", db)
    assert exc_info.value.status_code == 404


async def _read_export(response: Any) -> list[list[str]]:
    chunks: list[str] = []
    async for chunk in response.body_iterator:
        chunks.append(chunk)
    text = "".join(
        chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk for chunk in chunks
    )
    return list(csv.reader(io.StringIO(text)))


@pytest.mark.asyncio
async def test_export_ports_csv_shape(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    await _seed_ip(export_database)
    async with export_database() as db:
        response = await export_ports("198.51.100.7", db)
    header, *rows = await _read_export(response)
    assert header == ["IP", "Port", "State", "Service", "Banner"]
    assert rows[0][0] == "198.51.100.7"
    assert rows[0][1] == "443/tcp"
    assert rows[0][3] == "https"


@pytest.mark.asyncio
async def test_export_vulns_csv_shape(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    await _seed_ip(export_database)
    async with export_database() as db:
        response = await export_vulns("198.51.100.7", db)
    header, *rows = await _read_export(response)
    assert header == [
        "Target",
        "CVE/Template ID",
        "Severity",
        "Matched At",
        "Description",
    ]
    assert rows[0][0] == "198.51.100.7"
    assert rows[0][1] == "CVE-2026-0001"
    assert rows[0][2] == "high"


@pytest.mark.asyncio
async def test_export_endpoints_csv_shape(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    await _seed_ip(export_database)
    async with export_database() as db:
        response = await export_endpoints("198.51.100.7", db)
    header, *rows = await _read_export(response)
    assert header == ["Target", "URL", "Method", "Source"]
    assert rows[0][0] == "198.51.100.7"
    assert rows[0][1] == "https://example.com/admin"
    assert rows[0][2] == "GET"


async def _seed_domain(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory() as db:
        ip_record = await crud.create_ip(db, IPCreate(ip_address="198.51.100.7"))
        domain = await crud.get_domain_by_name(db, "example.com") or None
        if domain is None:
            domain = Domain(id=uuid.uuid4(), name="example.com")
            db.add(domain)
            await db.flush()
        sub = Subdomain(
            id=uuid.uuid4(),
            domain_id=domain.id,
            name="www.example.com",
            source="crtsh",
        )
        db.add(sub)
        await db.flush()
        await db.execute(
            insert(subdomain_ip_link).values(subdomain_id=sub.id, ip_id=ip_record.id)
        )
        await db.commit()


@pytest.mark.asyncio
async def test_export_domain_full_report_includes_subdomains(
    export_database: async_sessionmaker[AsyncSession],
) -> None:
    await _seed_domain(export_database)
    async with export_database() as db:
        response = await export_full_report("example.com", db)
    raw_body: Any = response.body
    if isinstance(raw_body, (bytes, bytearray)):
        raw_body = bytes(raw_body).decode("utf-8")
    payload = json.loads(raw_body)
    assert payload["target_type"] == "domain"
    assert payload["domain"]["name"] == "example.com"
    assert payload["subdomains"][0]["name"] == "www.example.com"
    assert payload["ips"][0]["ip"] == "198.51.100.7"


def test_resolve_target_classifies_ip_and_domain() -> None:
    assert _resolve_target("198.51.100.7")[1] == "ip"
    assert _resolve_target("example.com")[1] == "domain"
    with pytest.raises(HTTPException):
        _resolve_target("not a target ; rm -rf /")
