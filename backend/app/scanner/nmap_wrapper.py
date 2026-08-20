import importlib
import ipaddress
import json
import logging
import time
import xml.etree.ElementTree as ET
from typing import Any

from .models import NmapHop, NmapResult, NmapService
from .validator import validate_ports, validate_target


logger = logging.getLogger(__name__)
NMAP_OS_DISCOVERY_PORTS: tuple[str, ...] = ("1-1024", "12345", "54321")


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
            add_script(f"{service.port}/{service.protocol}:{script_id}", script)

    for script in getattr(host, "scripts_results", []) or []:
        if not isinstance(script, dict):
            continue
        add_script(str(script.get("id", "script")), script)
    return scripts


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


def run_nmap(target: str, ports: str | None = None) -> NmapResult:
    """Run Nmap through python-libnmap without shell command construction.

    Args:
        target: IP address, CIDR, or comma-separated target list.
        ports: Optional validated numeric port or range specification.

    Returns:
        A normalized list of discovered services and OS detection data.

    Raises:
        RuntimeError: If python-libnmap or the Nmap executable is unavailable.
        ValueError: If target or ports are invalid.
    """
    validated_target = validate_target(target)
    # OS fingerprinting (-O) can consume the entire host timeout and suppress
    # service results. Service detection is the source of truth for saved ports.
    options = (
        "-sV -O -sC --traceroute --osscan-guess -T4 --max-retries 2 --host-timeout 5m"
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
    return NmapResult(
        target=validated_target,
        services=services,
        os_detection=os_detection,
        scan_time=time.monotonic() - started_at,
        scripts_output=scripts_output,
        traceroute=_traceroute(process.stdout),
    )
