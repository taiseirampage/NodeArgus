import asyncio
import json
import subprocess
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.v1.endpoints.vuln import (
    create_vulnerability_scan,
    get_latest_vulnerabilities,
)
from app.db import crud
from app.db.models import Base, Vulnerability
from app.db.schemas import IPCreate
from app.scanner.nuclei_wrapper import NucleiResult, NucleiVulnerability, run_nuclei
from app.tasks import run_vuln_scan_task


@pytest_asyncio.fixture
async def vulnerability_database(
    tmp_path: Path,
) -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    database_path = tmp_path / "vulnerabilities.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{database_path}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    yield session_factory
    await engine.dispose()


def _finding(severity: str = "high") -> NucleiVulnerability:
    return NucleiVulnerability(
        template_id="CVE-2024-test",
        cve_id="CVE-2024-0001",
        name="Test vulnerability",
        severity=severity,  # type: ignore[arg-type]
        description="A test finding",
        matched_at="http://192.168.1.10/",
        found_at=datetime.now(timezone.utc),
    )


def test_nuclei_wrapper_uses_jsonl_flag() -> None:
    output = json.dumps(
        {
            "template-id": "test-template",
            "info": {
                "name": "Test finding",
                "severity": "high",
                "description": "Test description",
                "classification": {"cve-id": ["CVE-2024-0001"]},
            },
            "matched-at": "http://192.168.1.10/",
        }
    )
    completed = SimpleNamespace(returncode=0, stdout=output, stderr="")
    process = MagicMock(return_value=completed)

    with patch("app.scanner.nuclei_wrapper.subprocess.run", process):
        result = run_nuclei(
            "192.168.1.10",
            severity_filter="critical,high,medium",
            tags_filter="cve",
        )

    command = process.call_args.args[0]
    assert "-jsonl" in command
    assert "-json" not in command
    assert ["-timeout", "5"] == command[
        command.index("-timeout") : command.index("-timeout") + 2
    ]
    assert ["-retries", "1"] == command[
        command.index("-retries") : command.index("-retries") + 2
    ]
    assert ["-severity", "critical,high,medium"] == command[-4:-2]
    assert command[-2:] == ["-tags", "cve"]
    assert result.vulnerabilities[0].cve_id == "CVE-2024-0001"


def test_nuclei_wrapper_supports_proxy_user_agent_and_stealth_options() -> None:
    process = MagicMock(
        return_value=SimpleNamespace(returncode=0, stdout="", stderr="")
    )
    with patch("app.scanner.nuclei_wrapper.subprocess.run", process):
        run_nuclei(
            "192.168.1.10",
            proxy="http://proxy.example:8080",
            user_agent="NodeArgus-Test",
            stealth_mode=True,
        )

    command = process.call_args.args[0]
    assert command[command.index("-timeout") + 1] == "15"
    assert command[command.index("-rate-limit") + 1] == "10"
    assert command[command.index("-H") + 1] == "User-Agent: NodeArgus-Test"
    assert command[command.index("-proxy") + 1] == "http://proxy.example:8080"


def test_nuclei_wrapper_rejects_unsafe_proxy_and_user_agent() -> None:
    with pytest.raises(ValueError):
        run_nuclei("192.168.1.10", proxy="ftp://proxy.example:21")
    with pytest.raises(ValueError):
        run_nuclei("192.168.1.10", user_agent="bad\r\nX-Injected: true")


def test_nuclei_wrapper_returns_partial_results_on_timeout(tmp_path: Path) -> None:
    output_path = tmp_path / "nuclei-output.jsonl"
    partial_output = json.dumps(
        {
            "template-id": "partial-template",
            "info": {"name": "Partial finding", "severity": "high"},
            "matched-at": "192.168.1.10",
        }
    )

    def timeout_process(command: list[str], **kwargs: object) -> None:
        output_path.write_text(partial_output, encoding="utf-8")
        raise subprocess.TimeoutExpired(command, 300)

    with (
        patch("app.scanner.nuclei_wrapper.NUCLEI_OUTPUT_PATH", output_path),
        patch("app.scanner.nuclei_wrapper.subprocess.run", side_effect=timeout_process),
    ):
        result = run_nuclei(
            "192.168.1.10",
            severity_filter="critical,high,medium",
            tags_filter="cve",
        )

    assert result.timed_out is True
    assert len(result.vulnerabilities) == 1


async def _create_ip(
    session_factory: async_sessionmaker[AsyncSession],
) -> int:
    async with session_factory() as db:
        record = await crud.create_ip(db, IPCreate(ip_address="192.168.1.10"))
        return record.id


def test_vulnerability_task_uses_fresh_cache(
    vulnerability_database: async_sessionmaker[AsyncSession],
) -> None:
    ip_id = asyncio.run(_create_ip(vulnerability_database))
    asyncio.run(
        _save_finding(vulnerability_database, ip_id, datetime.now(timezone.utc))
    )
    with (
        patch("app.tasks.scan.AsyncSessionLocal", vulnerability_database),
        patch("app.tasks.scan.run_nuclei") as run_nuclei,
    ):
        result = run_vuln_scan_task.run("192.168.1.10", force=False)

    run_nuclei.assert_not_called()
    assert result["status"] == "cached"
    assert len(result["vulnerabilities"]) == 1


def test_vulnerability_task_force_runs_nuclei(
    vulnerability_database: async_sessionmaker[AsyncSession],
) -> None:
    ip_id = asyncio.run(_create_ip(vulnerability_database))
    asyncio.run(
        _save_finding(vulnerability_database, ip_id, datetime.now(timezone.utc))
    )
    with (
        patch("app.tasks.scan.AsyncSessionLocal", vulnerability_database),
        patch(
            "app.tasks.scan.run_nuclei",
            return_value=NucleiResult(target="192.168.1.10"),
        ) as run_nuclei,
    ):
        result = run_vuln_scan_task.run("192.168.1.10", force=True)

    run_nuclei.assert_called_once_with(
        "192.168.1.10",
        severity_filter="critical,high,medium",
    )
    assert result == {"status": "success", "vulnerabilities_count": 0}


def test_vulnerability_task_saves_findings(
    vulnerability_database: async_sessionmaker[AsyncSession],
) -> None:
    ip_id = asyncio.run(_create_ip(vulnerability_database))
    findings = [_finding("critical"), _finding("medium")]
    with (
        patch("app.tasks.scan.AsyncSessionLocal", vulnerability_database),
        patch(
            "app.tasks.scan.run_nuclei",
            return_value=NucleiResult(target="192.168.1.10", vulnerabilities=findings),
        ),
    ):
        result = run_vuln_scan_task.run("192.168.1.10", force=True)

    saved = asyncio.run(_get_findings(vulnerability_database, ip_id))
    assert result["vulnerabilities_count"] == 2
    assert len(saved) == 2
    assert [item.severity for item in saved] == ["critical", "medium"]


async def _save_finding(
    session_factory: async_sessionmaker[AsyncSession], ip_id: int, found_at: datetime
) -> None:
    async with session_factory() as db:
        finding = _finding()
        finding.found_at = found_at - timedelta(hours=1)
        await crud.save_vulnerabilities(db, ip_id, [finding])


async def _get_findings(
    session_factory: async_sessionmaker[AsyncSession],
    ip_id: int,
) -> list[Vulnerability]:
    async with session_factory() as db:
        return list(await crud.get_vulnerabilities_by_ip(db, ip_id))


@pytest.mark.asyncio
async def test_post_vulnerability_scan_returns_task_id(
    vulnerability_database: async_sessionmaker[AsyncSession],
) -> None:
    await _create_ip(vulnerability_database)
    with patch("app.api.v1.endpoints.vuln.run_vuln_scan_task") as task_proxy:
        task_proxy.delay.return_value = SimpleNamespace(id="vulnerability-task-1")
        async with vulnerability_database() as db:
            response = await create_vulnerability_scan("192.168.1.10", False, db)

    task_proxy.delay.assert_called_once_with("192.168.1.10", False)
    assert response.task_id == "vulnerability-task-1"
    assert response.status == "queued"


@pytest.mark.asyncio
async def test_latest_vulnerabilities_returns_cached_rows(
    vulnerability_database: async_sessionmaker[AsyncSession],
) -> None:
    ip_id = await _create_ip(vulnerability_database)
    async with vulnerability_database() as db:
        await crud.save_vulnerabilities(db, ip_id, [_finding()])
        response = await get_latest_vulnerabilities("192.168.1.10", db)

    assert response.status == "cached"
    assert response.vulnerabilities is not None
    assert response.vulnerabilities[0].name == "Test vulnerability"
