import importlib
import ipaddress
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from typing import Any

from .models import NmapHop, NmapResult, NmapService
from .validator import validate_ports, validate_target


logger = logging.getLogger(__name__)
NMAP_OS_DISCOVERY_PORTS: tuple[str, ...] = ("1-1024", "12345", "54321")
DEFAULT_SCRIPT_CATEGORIES: tuple[str, ...] = ("auth", "discovery", "broadcast")
_SCRIPT_CATEGORY_PATTERN = re.compile(r"^[a-z][a-z0-9]*$")
ANONYMOUS_ACCESS_MARKERS: tuple[str, ...] = (
    "anonymous ftp login allowed",
    "anonymous access allowed",
    "anonymous access enabled",
    "anonymous login enabled",
    "anonymous login allowed",
    "anonymous login successful",
)
ANONYMOUS_ACCESS_KEYWORDS: tuple[str, ...] = ("allowed", "enabled", "granted", "login")


def _validate_script_categories(script_categories: list[str]) -> list[str]:
    """Reject categories that are not safe Nmap script identifiers."""
    if not script_categories:
        raise ValueError("script category list must not be empty")
    validated: list[str] = []
    for category in script_categories:
        if not isinstance(category, str) or not _SCRIPT_CATEGORY_PATTERN.match(
            category
        ):
            raise ValueError(f"invalid script category: {category!r}")
        if category not in validated:
            validated.append(category)
    return validated


def _service_version(service: Any) -> str:
    service_dict = getattr(service, "service_dict", {}) or {}
    product = getattr(service, "service_product", "") or ""
    version = getattr(service, "service_version", "") or ""
    if isinstance(service_dict, dict):
        product = product or service_dict.get("product", "")
        version = version or service_dict.get("version", "")
    return " ".join(part for part in (product, version) if part)


def _service_name(service: Any) -> str:
    name = getattr(service, "service", "") or ""
    if name:
        return str(name)
    service_dict = getattr(service, "service_dict", {}) or {}
    if isinstance(service_dict, dict):
        return str(service_dict.get("name", "") or "")
    return ""


def _os_match(host: Any) -> str:
    host_os = getattr(host, "os", None)
    matches = getattr(host_os, "osmatches", []) if host_os else []
    if not matches:
        return ""
    match = matches[0]
    name = str(getattr(match, "name", "") or "")
    accuracy = str(getattr(match, "accuracy", "") or "")
    return f"{name} ({accuracy}%)" if name and accuracy else name


def _script_text(script: Any) -> str:
    if not isinstance(script, dict):
        return ""
    output = str(script.get("output", "") or "").strip()
    if output:
        return output[:4096]
    elements = script.get("elements")
    if isinstance(elements, dict) and elements:
        return json.dumps(elements, ensure_ascii=False, sort_keys=True)[:4096]
    return ""


def _scripts_output(host: Any) -> dict[str, str]:
    scripts: dict[str, str] = {}

    def add_script(key: str, script: Any) -> None:
        output = _script_text(script)
        if output:
            scripts[key] = output

    for service in getattr(host, "services", []) or []:
        service_scripts = getattr(service, "scripts_results", []) or []
        for script in service_scripts:
            if not isinstance(script, dict):
                continue
            script_id = str(script.get("id", "script"))
            add_script(script_id, script)

    for script in getattr(host, "scripts_results", []) or []:
        if not isinstance(script, dict):
            continue
        add_script(str(script.get("id", "script")), script)
    return scripts


def _scripts_from_xml(xml_output: str | bytes) -> dict[str, str]:
    """Extract NSE ``<script id=... output=...>`` blocks straight from the XML."""
    scripts: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_output)
    except (ET.ParseError, TypeError):
        return scripts
    for script in root.findall(".//script"):
        script_id = script.get("id")
        if not script_id:
            continue
        output = (script.get("output") or "").strip()
        if output:
            scripts[script_id] = output[:4096]
    return scripts


def _has_anonymous_access(scripts_output: dict[str, str]) -> bool:
    """Detect anonymous access (e.g. FTP Anonymous) in NSE auth script output."""
    for output in scripts_output.values():
        text = output.lower()
        if any(marker in text for marker in ANONYMOUS_ACCESS_MARKERS):
            return True
        if "anonymous" in text and any(
            keyword in text for keyword in ANONYMOUS_ACCESS_KEYWORDS
        ):
            return True
    return False


def _traceroute(xml_output: str | bytes) -> list[NmapHop]:
    try:
        root = ET.fromstring(xml_output)
    except (ET.ParseError, TypeError):
        return []

    hops: list[NmapHop] = []
    for trace in root.findall(".//trace"):
        for hop in trace.findall("hop"):
            try:
                ttl = int(hop.get("ttl", ""))
            except ValueError:
                continue
            ip = hop.get("ipaddr") or None
            hostname = hop.get("host") or None
            rtt = hop.get("rtt") or None
            if ip in {"*", "unknown"}:
                ip = None
            if ip is None:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            hops.append(NmapHop(ttl=ttl, ip=ip, hostname=hostname, rtt=rtt))
    return hops


def _scan_port_spec(ports: str | None) -> str | None:
    """Keep Masscan ports and add TCP ports useful for OS fingerprinting."""
    if ports is None:
        return None
    validated_ports = validate_ports(ports)
    requested_ports = validated_ports.split(",")
    combined_ports: list[str] = list(NMAP_OS_DISCOVERY_PORTS)
    combined_ports.extend(
        port for port in requested_ports if port not in combined_ports
    )
    return ",".join(combined_ports)


def run_nmap(
    target: str,
    ports: str | None = None,
    script_categories: list[str] | None = None,
) -> NmapResult:
    """Run Nmap through python-libnmap without shell command construction.

    Advanced NSE categories (``auth``, ``discovery``, ``broadcast``) collect
    service metadata, anonymous-access checks, and device discovery. The
    ``vuln`` category is intentionally excluded because vulnerability scans are
    delegated to Nuclei.

    Args:
        target: IP address, CIDR, or comma-separated target list.
        ports: Optional validated numeric port or range specification.
        script_categories: NSE script categories to enable. Defaults to
            ``("auth", "discovery", "broadcast")``.

    Returns:
        A normalized list of discovered services and OS detection data.

    Raises:
        RuntimeError: If python-libnmap or the Nmap executable is unavailable.
        ValueError: If target, ports, or script categories are invalid.
    """
    validated_target = validate_target(target)
    requested_categories = (
        script_categories
        if script_categories is not None
        else list(DEFAULT_SCRIPT_CATEGORIES)
    )
    validated_categories = _validate_script_categories(requested_categories)
    # OS fingerprinting (-O) can consume the entire host timeout and suppress
    # service results. Service detection is the source of truth for saved ports.
    # -sC keeps the default/safe scripts while --script adds the advanced NSE
    # categories on top of them (Nmap unions multiple script selections).
    options = (
        "-sV -O -sC "
        f"--script={','.join(validated_categories)} "
        "--traceroute --osscan-guess -T4 --max-retries 2 "
        "--host-timeout 30m --script-timeout 5m"
    )
    scan_ports = _scan_port_spec(ports)
    if scan_ports is not None:
        options = f"{options} -p {scan_ports}"
    try:
        nmap_process_module = importlib.import_module("libnmap.process")
        nmap_parser_module = importlib.import_module("libnmap.parser")
        nmap_process = nmap_process_module.NmapProcess
        nmap_parser = nmap_parser_module.NmapParser
    except (ImportError, ModuleNotFoundError, AttributeError) as error:
        logger.exception("python-libnmap is not installed")
        raise RuntimeError("python-libnmap is required to run Nmap") from error

    started_at = time.monotonic()
    try:
        process = nmap_process(targets=validated_target, options=options)
        process.run()
        report = nmap_parser.parse(process.stdout)
        services: list[NmapService] = []
        os_detection = ""
        scripts_output: dict[str, str] = {}
        for host in report.hosts:
            os_detection = os_detection or _os_match(host)
            scripts_output.update(_scripts_output(host))
            for service in host.services:
                service_name = _service_name(service)
                if int(service.port) == 443 and service_name == "http":
                    service_name = "https"
                logger.warning("=== NMAP SERVICE DETECTION ===")
                logger.warning(
                    "Port %s/%s: service=%s, state=%s, version=%s",
                    getattr(service, "port", "?"),
                    getattr(service, "protocol", "?"),
                    service_name or "unknown",
                    getattr(service, "state", "unknown"),
                    _service_version(service) or "unknown",
                )
                raw_state = getattr(service, "state", "unknown")
                if isinstance(raw_state, dict):
                    service_state = str(raw_state.get("state", "unknown"))
                else:
                    service_state = str(raw_state or "unknown")
                if service_state == "filtered":
                    service_name = "filtered"
                services.append(
                    NmapService(
                        port=int(service.port),
                        protocol=str(service.protocol),
                        service=service_name,
                        version=_service_version(service),
                        os_match=_os_match(host),
                        state=service_state,
                    )
                )
    except (OSError, RuntimeError, ValueError, AttributeError, TypeError) as error:
        logger.exception("Nmap scan failed for target %s", validated_target)
        raise RuntimeError(f"Nmap scan failed: {error}") from error
    logger.info("Nmap scan completed for %s", validated_target)
    if not os_detection or any(
        marker in os_detection.lower()
        for marker in ("no os matches", "too many fingerprints", "unknown")
    ):
        os_detection = "Unknown (Filtered)"
    raw_xml: str | bytes = getattr(process, "stdout", "") or ""
    xml_scripts = _scripts_from_xml(raw_xml)
    for script_id, output in xml_scripts.items():
        scripts_output.setdefault(script_id, output)
    return NmapResult(
        target=validated_target,
        services=services,
        os_detection=os_detection,
        scan_time=time.monotonic() - started_at,
        scripts_output=scripts_output,
        traceroute=_traceroute(raw_xml),
        has_anonymous_access=_has_anonymous_access(scripts_output),
    )
