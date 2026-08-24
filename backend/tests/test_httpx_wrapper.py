import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.httpx_wrapper import (
    HttpxError,
    _normalize_records,
    _parse_jsonl,
    run_httpx,
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
        '{"url":"https://a.com","status_code":200}\n'
        "\n"
        "not-json\n"
        '{"url":"https://b.com","status_code":301}\n'
    )
    records = _parse_jsonl(output)
    assert [record["url"] for record in records] == [
        "https://a.com",
        "https://b.com",
    ]


def test_normalize_records_extracts_target_fields() -> None:
    records = [
        {
            "url": "https://a.com",
            "status_code": 200,
            "title": "Example",
            "tech": ["nginx", "React"],
            "webserver": "nginx/1.25",
            "content_length": 123,
        }
    ]
    normalized = _normalize_records(records)
    assert normalized == [
        {
            "url": "https://a.com",
            "status_code": 200,
            "title": "Example",
            "tech": ["nginx", "React"],
            "web_server": "nginx/1.25",
            "content_length": 123,
        }
    ]


def test_normalize_skips_records_without_url() -> None:
    assert _normalize_records([{"status_code": 200}]) == []
    assert _normalize_records([{"url": ""}]) == []


def test_normalize_ignores_non_list_tech() -> None:
    normalized = _normalize_records([{"url": "https://a.com", "tech": "nginx"}])
    assert normalized[0]["tech"] == []


@pytest.mark.asyncio
async def test_run_httpx_writes_targets_to_list_and_parses_stdout() -> None:
    process = _exec_result(
        0, '{"url":"http://1.2.3.4:80","status_code":200,"title":"T"}\n'
    )
    with (
        patch(
            "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ) as create,
        patch(
            "app.scanner.httpx_wrapper._write_target_list",
            return_value="/tmp/fake-httpx.txt",
        ) as write_list,
    ):
        records = await run_httpx(["http://1.2.3.4:80"])

    args = list(create.call_args.args)
    assert args[0] == "httpx"
    assert "-list" in args
    assert "-title" in args and "-tech-detect" in args
    assert "-status-code" in args and "-content-length" in args
    assert "-web-server" in args
    write_list.assert_called_once_with(["http://1.2.3.4:80"])
    assert records[0]["url"] == "http://1.2.3.4:80"
    assert records[0]["status_code"] == 200


@pytest.mark.asyncio
async def test_run_httpx_rejects_unsafe_target_before_spawning() -> None:
    with patch(
        "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
    ) as create:
        with pytest.raises(ValueError):
            await run_httpx(["https://example.com; rm -rf /"])
        create.assert_not_called()


@pytest.mark.asyncio
async def test_run_httpx_reports_missing_binary() -> None:
    with patch(
        "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
        side_effect=FileNotFoundError("httpx"),
    ):
        with pytest.raises(HttpxError, match="not installed"):
            await run_httpx(["https://example.com"])


@pytest.mark.asyncio
async def test_run_httpx_times_out_while_spawning() -> None:
    with patch(
        "app.scanner.httpx_wrapper.asyncio.wait_for",
        side_effect=asyncio.TimeoutError,
    ):
        with pytest.raises(HttpxError, match="timed out"):
            await run_httpx(["https://example.com"])


@pytest.mark.asyncio
async def test_run_httpx_raises_on_nonzero_exit() -> None:
    process = _exec_result(2, "")
    process.stderr = _make_stream("fatal")
    with (
        patch(
            "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
    ):
        with pytest.raises(HttpxError, match="exit code 2"):
            await run_httpx(["https://example.com"])


@pytest.mark.asyncio
async def test_run_httpx_returns_partial_results_when_timeout_hits() -> None:
    process = SimpleNamespace()
    process.returncode = 0
    stdout_stream = asyncio.StreamReader()
    stdout_stream.feed_data(
        b'{"url":"http://1.2.3.4:80","status_code":200,"title":"T"}\n'
    )
    process.stdout = stdout_stream
    process.stderr = _make_stream("")
    process.kill = MagicMock()
    process.communicate = AsyncMock(return_value=(b"", b""))
    with (
        patch("app.scanner.httpx_wrapper.HTTTPX_TIMEOUT_SECONDS", 0.05),
        patch(
            "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
        patch(
            "app.scanner.httpx_wrapper._write_target_list",
            return_value="/tmp/fake-httpx.txt",
        ),
    ):
        records = await run_httpx(["http://1.2.3.4:80"])

    assert records[0]["url"] == "http://1.2.3.4:80"
    assert records[0]["status_code"] == 200
