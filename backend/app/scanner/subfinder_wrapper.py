import asyncio
import json
import logging
from typing import Any

from .validator import validate_domain


logger = logging.getLogger(__name__)

SUBFINDER_TIMEOUT_SECONDS = 300


class SubfinderError(RuntimeError):
    """Raised when Subfinder exits unsuccessfully or is unavailable."""


def _parse_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse Subfinder JSONL output into a list of normalized records.

    Subfinder emits one JSON object per line. Processing line-by-line lets us
    handle very large result sets without buffering the whole payload as one
    JSON array.

    Args:
        output: The raw stdout captured from Subfinder.

    Returns:
        A list of JSON objects produced by Subfinder.
    """
    records: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Ignoring malformed Subfinder JSONL line")
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


async def run_subfinder(domain: str) -> list[dict[str, Any]]:
    """Run Subfinder passively against a validated domain and return its records.

    Subfinder is invoked without a shell wrapper (``shell=False`` semantics via
    ``asyncio.create_subprocess_exec``), so the validated domain is passed as a
    single argv element and cannot be interpreted as shell syntax.

    Args:
        domain: A validated FQDN to enumerate subdomains for.

    Returns:
        A list of Subfinder output records (one per discovered subdomain).

    Raises:
        ValueError: If the domain is invalid.
        SubfinderError: If Subfinder fails, times out, or is not installed.
    """
    validated_domain = validate_domain(domain)
    command = [
        "subfinder",
        "-d",
        validated_domain,
        "-json",
        "-silent",
    ]
    logger.info("Running Subfinder for %s", validated_domain)
    try:
        process = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=SUBFINDER_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError as error:
        raise SubfinderError(
            f"Subfinder timed out after {SUBFINDER_TIMEOUT_SECONDS}s for "
            f"{validated_domain}"
        ) from error
    except FileNotFoundError as error:
        raise SubfinderError("subfinder binary is not installed") from error

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=SUBFINDER_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError as error:
        process.kill()
        await process.wait()
        raise SubfinderError(
            f"Subfinder timed out after {SUBFINDER_TIMEOUT_SECONDS}s for "
            f"{validated_domain}"
        ) from error

    if process.returncode != 0:
        stderr_text = stderr.decode("utf-8", errors="replace").strip()
        logger.error(
            "Subfinder failed for %s with exit code %d: %s",
            validated_domain,
            process.returncode,
            stderr_text,
        )
        raise SubfinderError(
            f"Subfinder failed for {validated_domain} with exit code "
            f"{process.returncode}: {stderr_text or 'unknown error'}"
        )

    stdout_text = stdout.decode("utf-8", errors="replace")
    records = _parse_jsonl(stdout_text)
    logger.info(
        "Subfinder completed for %s: %d subdomains",
        validated_domain,
        len(records),
    )
    return records
