import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from .validator import validate_web_target


logger = logging.getLogger(__name__)

HTTTPX_TIMEOUT_SECONDS = 600


class HttpxError(RuntimeError):
    """Raised when httpx exits unsuccessfully or is unavailable."""


def _parse_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse httpx JSONL stdout into a list of raw records."""
    records: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring malformed httpx JSONL line")
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _normalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce httpx raw JSON records to the fields the app persists."""
    normalized: list[dict[str, Any]] = []
    for record in records:
        url = record.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        raw_tech = record.get("tech")
        tech: list[str] = (
            [str(item) for item in raw_tech if isinstance(item, str)]
            if isinstance(raw_tech, list)
            else []
        )
        normalized.append(
            {
                "url": url,
                "status_code": record.get("status_code"),
                "title": record.get("title"),
                "tech": tech,
                "web_server": record.get("webserver"),
                "content_length": record.get("content_length"),
            }
        )
    return normalized


def _write_target_list(targets: list[str]) -> str:
    """Write one target per line to a temporary file for httpx ``-list``."""
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".txt", delete=False
    )
    try:
        for target in targets:
            handle.write(f"{target}\n")
    finally:
        handle.close()
    return handle.name


async def run_httpx(targets: list[str]) -> list[dict[str, Any]]:
    """Probe web targets with httpx and return normalized JSONL records.

    Targets are written to a temporary file and passed via ``-list`` so no user
    input ever reaches a shell; every value is validated by
    ``validate_web_target`` first. httpx is invoked with
    ``asyncio.create_subprocess_exec`` (argv array), so command injection is
    impossible.

    Args:
        targets: Web hosts to probe. Each entry is an ``http(s)://`` URL or a
            bare validated hostname/IP.

    Returns:
        A list of dicts with ``url``, ``status_code``, ``title``, ``tech``
        (list), ``web_server`` and ``content_length``. Returns an empty list
        when nothing responded.

    Raises:
        ValueError: If a target is unsafe or malformed.
        HttpxError: If httpx fails, times out, or is not installed.
    """
    if not targets:
        raise ValueError("targets must not be empty")
    validated_targets = [validate_web_target(target) for target in targets]

    list_path: str | None = None
    try:
        list_path = _write_target_list(validated_targets)
        command = [
            "httpx",
            "-list",
            list_path,
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-web-server",
            "-location",
        ]
        logger.info("Running httpx against %d web targets", len(validated_targets))
        try:
            process = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=HTTTPX_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as error:
            raise HttpxError(
                f"httpx timed out after {HTTTPX_TIMEOUT_SECONDS}s"
            ) from error
        except FileNotFoundError as error:
            raise HttpxError("httpx binary is not installed") from error

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=HTTTPX_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError as error:
            process.kill()
            await process.wait()
            raise HttpxError(
                f"httpx timed out after {HTTTPX_TIMEOUT_SECONDS}s"
            ) from error

        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            logger.error(
                "httpx failed with exit code %d: %s",
                process.returncode,
                stderr_text,
            )
            raise HttpxError(
                f"httpx failed with exit code {process.returncode}: "
                f"{stderr_text or 'unknown error'}"
            )

        stdout_text = stdout.decode("utf-8", errors="replace")
        records = _normalize_records(_parse_jsonl(stdout_text))
        logger.info("httpx completed: %d live web hosts", len(records))
        return records
    finally:
        if list_path is not None:
            Path(list_path).unlink(missing_ok=True)
