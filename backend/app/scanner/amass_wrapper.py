import asyncio
import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal

from app.config import settings

from .validator import validate_domain


logger = logging.getLogger(__name__)

PASSIVE_TIMEOUT_SECONDS = 180
ACTIVE_TIMEOUT_SECONDS = 600

# Amass v4 emits graph-relation lines on stdout, e.g.:
#   example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)
#   15169 (ASN) --> announces --> 93.184.216.0/24 (Netblock)
_FQDN_RE = re.compile(r"^\s*(?P<name>[^\s]+)\s+\(FQDN\)")
_IP_TARGET_RE = re.compile(r"-->\s*(?P<ip>[^\s]+)\s+\(IPAddress\)")
_ASN_RE = re.compile(
    r"^\s*(?P<asn>\d+)\s+\(ASN\)\s+-->\s+"
    r"(?P<edge>announces|managed_by)\s+-->\s+"
    r"(?P<target>.+?)\s+\((?:Netblock|RIROrganization)\)"
)


class AmassError(RuntimeError):
    """Raised when Amass exits unsuccessfully or is unavailable."""


def _parse_lines(output: str) -> list[str]:
    """Return the non-empty stripped lines of Amass output."""
    return [line.strip() for line in output.splitlines() if line.strip()]


def _parse_records(output: str, root_domain: str) -> dict[str, Any]:
    """Reduce Amass stdout into the normalized result structure.

    Amass v4 writes graph relations such as ``name (FQDN) --> a_record -->
    addr (IPAddress)``, Netblock containment lines and ASN announcements. We use
    those to derive subdomains, per-subdomain resolved IPs, global IPs, and
    ASN/CIDR attribution while filtering out unrelated FQDNs discovered via
    NS/MX/CNAME records.

    Args:
        output: The raw stdout captured from Amass.
        root_domain: The validated FQDN under which subdomains are retained.

    Returns:
        A dict with ``subdomains``, ``ip_addresses``, ``asn_info`` and a
        per-subdomain ``resolved`` mapping ``{name: [ip, ...]}``.
    """
    resolved: dict[str, set[str]] = {}
    ip_records: set[str] = set()
    iasn: dict[int, dict[str, Any]] = {}

    for line in _parse_lines(output):
        fqdn_match = _FQDN_RE.match(line)
        current_name: str | None = None
        if fqdn_match:
            raw_name = fqdn_match.group("name").rstrip(".").lower()
            if raw_name != root_domain and raw_name.endswith("." + root_domain):
                current_name = raw_name

        ip_match = _IP_TARGET_RE.search(line)
        if ip_match:
            raw = ip_match.group("ip")
            try:
                ipaddress.ip_address(raw)
            except ValueError:
                logger.warning("Ignoring invalid IP in Amass output: %s", raw)
                continue
            ip_records.add(raw)
            if current_name is not None:
                resolved.setdefault(current_name, set()).add(raw)

        asn_match = _ASN_RE.match(line)
        if asn_match:
            asn_number = int(asn_match.group("asn"))
            edge = asn_match.group("edge")
            target = asn_match.group("target").strip()
            entry = iasn.setdefault(
                asn_number,
                {"asn_number": asn_number, "cidr": None, "description": None},
            )
            if edge == "announces" and "/" in target:
                if entry["cidr"] is None:
                    entry["cidr"] = target
            elif edge == "managed_by":
                if entry["description"] is None:
                    entry["description"] = target

    return {
        "subdomains": sorted(resolved),
        "resolved": {name: sorted(ips) for name, ips in resolved.items()},
        "asn_info": sorted(iasn.values(), key=lambda item: item["asn_number"]),
        "ip_addresses": sorted(ip_records),
    }


def _has_active_recon_permission(mode: str) -> bool:
    """Return whether an active recon mode is permitted by configuration.

    Active brute forcing generates noticeable DNS noise and touches many
    third-party resolvers, so it is gated behind ``ALLOW_ACTIVE_RECON``.
    """
    if mode != "active":
        return True
    if not settings.ALLOW_ACTIVE_RECON:
        logger.warning(
            "Active Amass recon disabled: set ALLOW_ACTIVE_RECON=true to allow"
        )
        return False
    return True


def _build_command(domain: str, mode: str) -> list[str]:
    """Assemble the Amass argv array for the requested mode.

    The domain is validated first and passed as a single argv element, so it
    cannot be interpreted as shell syntax.

    Args:
        domain: The validated root FQDN.
        mode: ``passive`` or ``active``.

    Returns:
        A list of arguments suitable for ``asyncio.create_subprocess_exec``.
    """
    if mode == "active":
        wordlist = settings.AMASS_WORDLIST_PATH
        if not Path(wordlist).exists():
            raise AmassError(f"Amass brute-force wordlist not found: {wordlist}")
        return [
            "amass",
            "enum",
            "-d",
            domain,
            "-brute",
            "-w",
            wordlist,
            "-dns-qps",
            "10",
            "-config",
            settings.AMASS_CONF_PATH,
            "-timeout",
            str(ACTIVE_TIMEOUT_SECONDS // 60),
        ]
    return [
        "amass",
        "enum",
        "-passive",
        "-d",
        domain,
        "-config",
        settings.AMASS_CONF_PATH,
        "-timeout",
        str(PASSIVE_TIMEOUT_SECONDS // 60),
    ]


async def run_amass(
    domain: str, mode: Literal["passive", "active"] = "passive"
) -> dict[str, Any]:
    """Run Amass against a validated domain and return normalized results.

    Amass is invoked without a shell wrapper (``asyncio.create_subprocess_exec``)
    and the validated domain is passed as a single argv element, preventing
    command injection.

    Args:
        domain: A validated FQDN to enumerate.
        mode: ``passive`` (data sources only) or ``active`` (adds DNS brute
            forcing). Active mode is gated by ``ALLOW_ACTIVE_RECON``.

    Returns:
        A dict with ``subdomains`` (list[str]), ``asn_info`` (list[dict]) and
        ``ip_addresses`` (list[str]). All fields are empty when nothing is found;
        the function never raises for empty results.

    Raises:
        ValueError: If the domain is invalid.
        AmassError: If active recon is disabled, the wordlist is missing, Amass
            fails, times out, or is not installed.
    """
    validated_domain = validate_domain(domain)
    if not _has_active_recon_permission(mode):
        raise AmassError(
            "active recon is disabled (allow_active_recon=false); skipping Amass"
        )

    command = _build_command(validated_domain, mode)
    timeout = ACTIVE_TIMEOUT_SECONDS if mode == "active" else PASSIVE_TIMEOUT_SECONDS
    logger.info(
        "Running Amass for %s in %s mode (%d subcommands args)",
        validated_domain,
        mode,
        len(command),
    )
    try:
        process = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "XDG_CONFIG_HOME": "/root/.config"},
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError as error:
        raise AmassError(
            f"Amass timed out after {timeout}s for {validated_domain}"
        ) from error
    except FileNotFoundError as error:
        raise AmassError("amass binary is not installed") from error

    stdout_text, stderr_text, timed_out = await _stream_output(process, timeout)
    if timed_out:
        logger.warning(
            "Amass timed out for %s; persisting partial results", validated_domain
        )
        result = _parse_records(stdout_text, validated_domain)
        result["partial"] = True
        return result

    if process.returncode != 0:
        stderr_text = stderr_text.strip()
        logger.error(
            "Amass failed for %s with exit code %d: %s",
            validated_domain,
            process.returncode,
            stderr_text,
        )
        raise AmassError(
            f"Amass failed for {validated_domain} with exit code "
            f"{process.returncode}: {stderr_text or 'unknown error'}"
        )

    result = _parse_records(stdout_text, validated_domain)
    logger.info(
        "Amass(%s) completed for %s: %d subdomains, %d IPs, %d ASNs",
        mode,
        validated_domain,
        len(result["subdomains"]),
        len(result["ip_addresses"]),
        len(result["asn_info"]),
    )
    return result


async def _stream_output(
    process: asyncio.subprocess.Process, timeout: int
) -> tuple[str, str, bool]:
    """Read Amass stdout/stderr until EOF or the deadline, whichever is first.

    Amass v4 writes graph relations to stdout progressively and only exits after
    its ``-timeout`` idle window plus graph shutdown. Instead of waiting for a
    clean exit, we read as much as the deadline allows so partial results can be
    persisted when the hard limit is reached.

    Args:
        process: The running Amass subprocess.
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
