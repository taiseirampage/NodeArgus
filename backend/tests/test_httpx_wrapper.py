import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.httpx_wrapper import (
    HttpxError,
    _normalize_records,
    _parse_jsonl,
    run_httpx,
)


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
    process = SimpleNamespace(
        returncode=0,
        stdout=b'{"url":"http://1.2.3.4:80","status_code":200,"title":"T"}\n',
        stderr=b"",
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
        patch.object(
            process, "communicate", new_callable=AsyncMock, create=True
        ) as comm,
    ):
        comm.return_value = (process.stdout, process.stderr)
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
    process = SimpleNamespace(returncode=2, stdout=b"", stderr=b"fatal")
    with (
        patch(
            "app.scanner.httpx_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
        patch.object(
            process, "communicate", new_callable=AsyncMock, create=True
        ) as comm,
    ):
        comm.return_value = (process.stdout, process.stderr)
        with pytest.raises(HttpxError, match="exit code 2"):
            await run_httpx(["https://example.com"])
