import asyncio
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, patch

import pytest

from app.scanner.subfinder_wrapper import (
    SubfinderError,
    _parse_jsonl,
    run_subfinder,
)


def test_parse_jsonl_returns_object_per_line() -> None:
    output = (
        '{"host":"a.example.com","source":"crtsh"}\n'
        '{"host":"b.example.com","source":"hackertarget"}\n'
    )
    records = _parse_jsonl(output)
    assert records == [
        {"host": "a.example.com", "source": "crtsh"},
        {"host": "b.example.com", "source": "hackertarget"},
    ]


def test_parse_jsonl_ignores_empty_and_malformed_lines() -> None:
    output = '{"host":"a.example.com"}\n\nnot-json\n{"host":"b.example.com"}\n'
    records = _parse_jsonl(output)
    assert [record["host"] for record in records] == [
        "a.example.com",
        "b.example.com",
    ]


def test_parse_jsonl_returns_empty_for_blank_output() -> None:
    assert _parse_jsonl("") == []
    assert _parse_jsonl("   \n\n  ") == []


@pytest.mark.asyncio
async def test_run_subfinder_parses_stdout_and_uses_validated_domain() -> None:
    process = SimpleNamespace(
        returncode=0,
        stdout=(
            b'{"host":"a.example.com","source":"crtsh"}\n'
            b'{"host":"b.example.com","source":"alienvault"}\n'
        ),
        stderr=b"",
    )
    with (
        patch(
            "app.scanner.subfinder_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ) as create,
        patch.object(
            process, "communicate", new_callable=AsyncMock, create=True
        ) as comm,
    ):
        comm.return_value = (process.stdout, process.stderr)
        records = await run_subfinder("Example.COM")

    create.assert_called_once_with(
        "subfinder",
        "-d",
        "example.com",
        "-json",
        "-silent",
        stdout=ANY,
        stderr=ANY,
    )
    assert [record["host"] for record in records] == [
        "a.example.com",
        "b.example.com",
    ]


@pytest.mark.asyncio
async def test_run_subfinder_raises_on_nonzero_exit() -> None:
    process = SimpleNamespace(
        returncode=2, stdout=b"", stderr=b"fatal: provider failed"
    )
    with (
        patch(
            "app.scanner.subfinder_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ) as create,
        patch.object(
            process, "communicate", new_callable=AsyncMock, create=True
        ) as comm,
    ):
        comm.return_value = (process.stdout, process.stderr)
        with pytest.raises(SubfinderError, match="exit code 2"):
            await run_subfinder("example.com")
    create.assert_called_once()


@pytest.mark.asyncio
async def test_run_subfinder_rejects_invalid_domain_before_spawning() -> None:
    with patch(
        "app.scanner.subfinder_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
    ) as create:
        with pytest.raises(ValueError):
            await run_subfinder("example.com; rm -rf /")
    create.assert_not_called()


@pytest.mark.asyncio
async def test_run_subfinder_reports_missing_binary() -> None:
    with patch(
        "app.scanner.subfinder_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
        side_effect=FileNotFoundError("subfinder"),
    ):
        with pytest.raises(SubfinderError, match="not installed"):
            await run_subfinder("example.com")


@pytest.mark.asyncio
async def test_run_subfinder_times_out_while_spawning() -> None:
    with patch(
        "app.scanner.subfinder_wrapper.asyncio.wait_for",
        side_effect=asyncio.TimeoutError,
    ):
        with pytest.raises(SubfinderError, match="timed out"):
            await run_subfinder("example.com")
