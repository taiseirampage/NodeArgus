import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .validator import validate_target


logger = logging.getLogger(__name__)
Severity = Literal["critical", "high", "medium", "low", "info"]
NUCLEI_OUTPUT_PATH = Path("/tmp/nuclei_output.json")
NUCLEI_SCAN_TIMEOUT_SECONDS = 300
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_NUCLEI_OPTIONS: list[str] = [
    "-jsonl",
    "-silent",
    "-timeout",
    "5",
    "-retries",
    "1",
    "-rate-limit",
    "150",
    "-concurrency",
    "25",
    "-max-host-error",
    "3",
    "-bulk-size",
    "25",
]


class NucleiVulnerability(BaseModel):
    """Normalized vulnerability data emitted by Nuclei."""

    template_id: str = Field(min_length=1, max_length=255)
    cve_id: str | None = Field(default=None, max_length=32)
    name: str = Field(min_length=1, max_length=512)
    severity: Severity
    description: str = Field(default="", max_length=4096)
    matched_at: str = Field(min_length=1, max_length=2048)
    found_at: datetime


class NucleiResult(BaseModel):
    """Normalized result returned by one Nuclei invocation."""

    target: str
    vulnerabilities: list[NucleiVulnerability] = Field(default_factory=list)
    timed_out: bool = False


def _cve_id(classifications: Any) -> str | None:
    if not isinstance(classifications, dict):
        return None
    value = classifications.get("cve-id", classifications.get("cve_id"))
    if isinstance(value, list):
        value = value[0] if value else None
    return str(value)[:32] if value else None


def _parse_record(record: Any, target: str) -> NucleiVulnerability | None:
    if not isinstance(record, dict):
        logger.warning("Ignoring malformed Nuclei record: expected an object")
        return None
    info = record.get("info")
    if not isinstance(info, dict):
        info = {}
    try:
        return NucleiVulnerability(
            template_id=str(record.get("template-id", record.get("template_id", ""))),
            cve_id=_cve_id(info.get("classification", info.get("classifications"))),
            name=str(info.get("name", "Nuclei finding")),
            severity=cast(Severity, str(info.get("severity", "info")).lower()),
            description=str(info.get("description", "") or ""),
            matched_at=str(record.get("matched-at", record.get("matched_at", target))),
            found_at=datetime.now(timezone.utc),
        )
    except (TypeError, ValueError) as error:
        logger.warning("Ignoring invalid Nuclei finding: %s", error)
        return None


def _parse_output(output: str, target: str) -> list[NucleiVulnerability]:
    if not output.strip():
        return []
    records: list[Any] = []
    try:
        parsed = json.loads(output)
        records = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning("Ignoring malformed Nuclei JSON output line")
    return [
        vulnerability
        for record in records
        if (vulnerability := _parse_record(record, target)) is not None
    ]


def _output_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    return output


def validate_proxy(proxy: str) -> str:
    """Validate an HTTP(S) or SOCKS5 proxy URL before passing it to Nuclei."""
    if not proxy or len(proxy) > 2048 or any(char in proxy for char in "\r\n\t "):
        raise ValueError("proxy must be a compact URL without control characters")
    parsed = urlsplit(proxy)
    if parsed.scheme.lower() not in {"http", "https", "socks5"}:
        raise ValueError("proxy scheme must be http, https, or socks5")
    if not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("proxy must contain a hostname without query or fragment")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("proxy port must be numeric") from error
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("proxy port must be between 1 and 65535")
    return proxy


def validate_user_agent(user_agent: str | None) -> str:
    """Validate a custom HTTP User-Agent and provide a browser default."""
    value = user_agent or DEFAULT_USER_AGENT
    if len(value) > 512 or any(char in value for char in "\r\n"):
        raise ValueError("user_agent contains invalid header characters")
    return value


def _read_output(stdout: str | bytes | None) -> str:
    if NUCLEI_OUTPUT_PATH.exists():
        try:
            return NUCLEI_OUTPUT_PATH.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            logger.warning("Unable to read Nuclei output file: %s", error)
    return _output_text(stdout)


def _build_command(
    target: str,
    severity_filter: str | None,
    tags_filter: str | None,
    proxy: str | None,
    user_agent: str | None,
    stealth_mode: bool,
) -> list[str]:
    options = list(DEFAULT_NUCLEI_OPTIONS)
    if stealth_mode:
        options[options.index("-timeout") + 1] = "15"
        options[options.index("-rate-limit") + 1] = "10"
    command = [
        "nuclei",
        "-target",
        target,
        *options,
        "-o",
        str(NUCLEI_OUTPUT_PATH),
    ]
    command.extend(["-H", f"User-Agent: {validate_user_agent(user_agent)}"])
    if proxy:
        command.extend(["-proxy", validate_proxy(proxy)])
    if severity_filter:
        command.extend(["-severity", severity_filter])
    if tags_filter:
        command.extend(["-tags", tags_filter])
    return command


def run_nuclei(
    target: str,
    severity_filter: str | None = None,
    tags_filter: str | None = None,
    proxy: str | None = None,
    user_agent: str | None = None,
    stealth_mode: bool = False,
) -> NucleiResult:
    """Run Nuclei with validated arguments and normalize JSONL findings.

    Nuclei is installed as a system executable in the application image. Scanner
    failures are logged and represented as an empty result so a missing optional
    scanner cannot crash the API process.
    """
    validated_target = validate_target(target)
    command = _build_command(
        validated_target,
        severity_filter,
        tags_filter,
        proxy,
        user_agent,
        stealth_mode,
    )
    try:
        NUCLEI_OUTPUT_PATH.unlink(missing_ok=True)
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=NUCLEI_SCAN_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            logger.error(
                "Nuclei failed for %s with exit code %d: %s",
                validated_target,
                completed.returncode,
                completed.stderr.strip(),
            )
            return NucleiResult(target=validated_target)
        output = _read_output(completed.stdout)
        vulnerabilities = _parse_output(output, validated_target)
        logger.info(
            "Nuclei completed for %s: %d vulnerabilities",
            validated_target,
            len(vulnerabilities),
        )
        return NucleiResult(target=validated_target, vulnerabilities=vulnerabilities)
    except subprocess.TimeoutExpired as error:
        partial_output = _read_output(error.stdout)
        vulnerabilities = _parse_output(partial_output, validated_target)
        logger.warning("Nuclei scan timeout after 300s, returning partial results")
        return NucleiResult(
            target=validated_target,
            vulnerabilities=vulnerabilities,
            timed_out=True,
        )
    except (FileNotFoundError, OSError, UnicodeError) as error:
        logger.exception("Nuclei is unavailable or failed for %s", validated_target)
        return NucleiResult(target=validated_target)
    finally:
        try:
            NUCLEI_OUTPUT_PATH.unlink(missing_ok=True)
        except OSError:
            logger.warning("Unable to remove Nuclei output file %s", NUCLEI_OUTPUT_PATH)
