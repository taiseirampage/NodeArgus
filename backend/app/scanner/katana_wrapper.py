import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .validator import validate_web_target


logger = logging.getLogger(__name__)

KATANA_TIMEOUT_SECONDS = 600
KATANA_MAX_DEPTH = 3
KATANA_EXCLUDED_EXTENSIONS = "png,jpg,jpeg,gif,css,js,svg,ico,woff,woff2,eot,ttf"
KATANA_RATE_LIMIT = 20
KATANA_CONCURRENCY = 5


class KatanaError(RuntimeError):
    """Raised when katana exits unsuccessfully or is unavailable."""


def _parse_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse katana JSONL stdout into a list of raw records."""
    records: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring malformed katana JSONL line")
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _origin(endpoint: str) -> str:
    """Return the ``scheme://netloc`` origin of a URL for grouping."""
    try:
        parsed = urlsplit(endpoint)
    except ValueError:
        return ""
    if not parsed.scheme and not parsed.netloc:
        return endpoint.rsplit("/", 1)[0]
    return f"{parsed.scheme}://{parsed.netloc}"


def _normalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce katana raw JSON records to endpoint records the app persists."""
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        request = record.get("request")
        endpoint: str | None = None
        method: str = "GET"
        if isinstance(request, dict):
            candidate = request.get("endpoint")
            if isinstance(candidate, str):
                endpoint = candidate
            raw_method = request.get("method")
            method = str(raw_method) if isinstance(raw_method, str) else "GET"
        if endpoint is None:
            candidate = record.get("endpoint")
            endpoint = str(candidate) if isinstance(candidate, str) else None
        if not endpoint or not endpoint.strip():
            continue
        endpoint = endpoint.strip()
        if endpoint in seen:
            continue
        seen.add(endpoint)

        raw_source = record.get("source")
        source = str(raw_source) if isinstance(raw_source, str) and raw_source else ""
        if not source:
            source = _origin(endpoint)
        normalized.append(
            {
                "endpoint": endpoint,
                "method": method,
                "source": source,
                "timestamp": record.get("timestamp"),
            }
        )
    return normalized


def _write_target_list(urls: list[str]) -> str:
    """Write one URL per line to a temporary file for katana ``-list``."""
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".txt", delete=False
    )
    try:
        for url in urls:
            handle.write(f"{url}\n")
    finally:
        handle.close()
    return handle.name


async def _stream_output(
    process: asyncio.subprocess.Process, timeout: int
) -> tuple[str, str, bool]:
    """Read katana stdout/stderr until EOF or the deadline, whichever is first.

    katana can generate a very large endpoint stream and only exits after its
    own idle timeout, so waiting for a clean exit would discard already-produced
    JSONL. Reading stdout progressively lets the caller persist partial results
    when the hard wall-clock deadline is reached.

    Args:
        process: The running katana subprocess.
        timeout: Hard wall-clock deadline in seconds.

    Returns:
        ``(stdout_text, stderr_text, timed_out)``. ``timed_out`` is True when the
        deadline was reached before the process exited.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    stdout_chunks: list[bytes] = []
    timed_out = False
    if process.stdout is None:
        process.kill()
        await process.communicate()
        return "", "", True
    while True:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            timed_out = True
            break
        try:
            chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=remaining)
        except asyncio.TimeoutError:
            timed_out = True
            break
        if not chunk:
            break
        stdout_chunks.append(chunk)

    stderr_text = ""
    if not timed_out and process.stderr is not None:
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining > 0:
            stderr_text = (
                await asyncio.wait_for(process.stderr.read(), timeout=remaining)
            ).decode("utf-8", errors="replace")
    if timed_out:
        process.kill()
    await asyncio.wait_for(process.communicate(), timeout=5)
    stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
    return stdout, stderr_text, timed_out


async def run_katana(urls: list[str]) -> list[dict[str, Any]]:
    """Crawl web URLs with katana and return normalized JSONL endpoint records.

    URLs are written to a temporary file and passed via ``-list``; every value
    is validated by ``validate_web_target`` first. katana is invoked with
    ``asyncio.create_subprocess_exec`` (argv array), so no user input reaches a
    shell.

    Args:
        urls: Full ``http(s)://`` URLs to crawl.

    Returns:
        A list of dicts with ``endpoint``, ``method``, ``source`` and
        ``timestamp``, deduplicated by endpoint. Returns partial results when
        the crawl hits its wall-clock timeout.

    Raises:
        ValueError: If a URL is unsafe or malformed.
        KatanaError: If katana fails, times out while spawning, or is not
            installed.
    """
    if not urls:
        raise ValueError("urls must not be empty")
    validated_urls = [validate_web_target(url) for url in urls]

    list_path: str | None = None
    try:
        list_path = _write_target_list(validated_urls)
        command = [
            "katana",
            "-list",
            list_path,
            "-jsonl",
            "-silent",
            "-d",
            str(KATANA_MAX_DEPTH),
            "-ef",
            KATANA_EXCLUDED_EXTENSIONS,
            "-rl",
            str(KATANA_RATE_LIMIT),
            "-c",
            str(KATANA_CONCURRENCY),
            "-no-color",
        ]
        logger.info("Running katana against %d URLs", len(validated_urls))
        try:
            process = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=KATANA_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as error:
            raise KatanaError(
                f"katana timed out after {KATANA_TIMEOUT_SECONDS}s"
            ) from error
        except FileNotFoundError as error:
            raise KatanaError("katana binary is not installed") from error

        stdout_text, stderr_text, timed_out = await _stream_output(
            process, KATANA_TIMEOUT_SECONDS
        )
        if timed_out:
            logger.warning(
                "katana timed out after %ds; persisting partial results",
                KATANA_TIMEOUT_SECONDS,
            )
            return _normalize_records(_parse_jsonl(stdout_text))

        if process.returncode != 0:
            stderr_text = stderr_text.strip()
            logger.error(
                "katana failed with exit code %d: %s",
                process.returncode,
                stderr_text,
            )
            raise KatanaError(
                f"katana failed with exit code {process.returncode}: "
                f"{stderr_text or 'unknown error'}"
            )

        records = _normalize_records(_parse_jsonl(stdout_text))
        logger.info("katana completed: %d endpoints discovered", len(records))
        return records
    finally:
        if list_path is not None:
            Path(list_path).unlink(missing_ok=True)
