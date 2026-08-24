import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.katana_wrapper import (
    KATANA_CONCURRENCY,
    KATANA_MAX_DEPTH,
    KatanaError,
    _normalize_records,
    _parse_jsonl,
    _origin,
    run_katana,
)


def _make_stream(data: str) -> MagicMock:
    """Return a stream whose ``read`` yields the data once, then EOF."""
    stream = MagicMock()
    reader = io.BytesIO(data.encode())
    stream.read = AsyncMock(side_effect=[reader.read(4096), b""])
    return stream


def _exec_result(returncode: int, stdout: str) -> SimpleNamespace:
    process = SimpleNamespace()
    process.returncode = returncode
    process.stdout = _make_stream(stdout)
    process.stderr = _make_stream("")
    process.kill = MagicMock()
    process.communicate = AsyncMock(return_value=(b"", b""))
    return process


def test_parse_jsonl_ignores_empty_and_malformed_lines() -> None:
    output = (
        '{"timestamp":"t","request":{"method":"GET","endpoint":"https://a.com/x"}}\n'
        "\n"
        "garbage\n"
        '{"timestamp":"t2","request":{"method":"POST","endpoint":"https://a.com/y"}}\n'
    )
    records = _parse_jsonl(output)
    assert len(records) == 2


def test_origin_extracts_scheme_and_netloc() -> None:
    assert _origin("https://sub.example.com/admin") == "https://sub.example.com"


def test_normalize_records_extracts_endpoint_fields_and_dedupes() -> None:
    records = [
        {
            "timestamp": "2026-01-01",
            "request": {"method": "GET", "endpoint": "https://a.com/login"},
        },
        {
            "timestamp": "2026-01-02",
            "request": {"method": "POST", "endpoint": "https://a.com/api"},
            "source": "https://a.com/login",
        },
        {
            "timestamp": "2026-01-03",
            "request": {"method": "GET", "endpoint": "https://a.com/login"},
        },
    ]
    normalized = _normalize_records(records)
    assert normalized[0] == {
        "endpoint": "https://a.com/login",
        "method": "GET",
        "source": "https://a.com",
        "timestamp": "2026-01-01",
    }
    assert normalized[1]["method"] == "POST"
    assert normalized[1]["source"] == "https://a.com/login"
    assert len(normalized) == 2


def test_normalize_falls_back_to_hostname_without_dot() -> None:
    normalized = _normalize_records(
        [
            {
                "request": {
                    "method": "GET",
                    "endpoint": "https://localhost:8080/admin",
                }
            }
        ]
    )
    assert normalized[0]["source"] == "https://localhost:8080"


@pytest.mark.asyncio
async def test_run_katana_writes_urls_to_list_and_parses_stdout() -> None:
    process = _exec_result(
        0,
        '{"request":{"method":"GET","endpoint":"https://a.com/login"}}\n'
        '{"request":{"method":"GET","endpoint":"https://a.com/register"}}\n',
    )
    with (
        patch(
            "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ) as create,
        patch(
            "app.scanner.katana_wrapper._write_target_list",
            return_value="/tmp/fake-katana.txt",
        ) as write_list,
    ):
        records = await run_katana(["https://a.com"])

    args = list(create.call_args.args)
    assert args[0] == "katana"
    assert "-list" in args
    assert "-jsonl" in args
    assert "-d" in args
    assert args[args.index("-d") + 1] == str(KATANA_MAX_DEPTH)
    assert "-ef" in args and "-no-color" in args
    assert args[args.index("-c") + 1] == str(KATANA_CONCURRENCY)
    write_list.assert_called_once_with(["https://a.com"])
    assert [record["endpoint"] for record in records] == [
        "https://a.com/login",
        "https://a.com/register",
    ]


@pytest.mark.asyncio
async def test_run_katana_rejects_unsafe_url_before_spawning() -> None:
    with patch(
        "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
    ) as create:
        with pytest.raises(ValueError):
            await run_katana(["https://a.com; touch /tmp/pwned"])
        create.assert_not_called()


@pytest.mark.asyncio
async def test_run_katana_rejects_non_http_scheme() -> None:
    with patch(
        "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
    ) as create:
        with pytest.raises(ValueError, match="only http/https"):
            await run_katana(["file:///etc/passwd"])
        create.assert_not_called()


@pytest.mark.asyncio
async def test_run_katana_reports_missing_binary() -> None:
    with patch(
        "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
        side_effect=FileNotFoundError("katana"),
    ):
        with pytest.raises(KatanaError, match="not installed"):
            await run_katana(["https://a.com"])


@pytest.mark.asyncio
async def test_run_katana_times_out_while_spawning() -> None:
    with patch(
        "app.scanner.katana_wrapper.asyncio.wait_for",
        side_effect=asyncio.TimeoutError,
    ):
        with pytest.raises(KatanaError, match="timed out"):
            await run_katana(["https://a.com"])


@pytest.mark.asyncio
async def test_run_katana_raises_on_nonzero_exit() -> None:
    process = _exec_result(3, "")
    process.stderr = _make_stream("boom")
    with (
        patch(
            "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
    ):
        with pytest.raises(KatanaError, match="exit code 3"):
            await run_katana(["https://a.com"])


@pytest.mark.asyncio
async def test_run_katana_returns_partial_results_when_timeout_hits() -> None:
    process = SimpleNamespace()
    process.returncode = 0
    stdout_stream = asyncio.StreamReader()
    stdout_stream.feed_data(
        b'{"request":{"method":"GET","endpoint":"https://a.com/login"}}\n'
    )
    process.stdout = stdout_stream
    process.stderr = _make_stream("")
    process.kill = MagicMock()
    process.communicate = AsyncMock(return_value=(b"", b""))
    with (
        patch("app.scanner.katana_wrapper.KATANA_TIMEOUT_SECONDS", 0.05),
        patch(
            "app.scanner.katana_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
        patch(
            "app.scanner.katana_wrapper._write_target_list",
            return_value="/tmp/fake-katana.txt",
        ),
    ):
        records = await run_katana(["https://a.com"])

    assert [record["endpoint"] for record in records] == ["https://a.com/login"]
