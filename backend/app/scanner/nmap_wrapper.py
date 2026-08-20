import importlib
import logging
import time
from typing import Any

from .models import NmapResult, NmapService
from .validator import validate_ports, validate_target


logger = logging.getLogger(__name__)


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
    return str(getattr(matches[0], "name", "") or "")


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
    options = "-sV -T4 --max-retries 1 --host-timeout 120s"
    if ports is not None:
        options = f"{options} -p {validate_ports(ports)}"
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
        for host in report.hosts:
            os_detection = os_detection or _os_match(host)
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
                services.append(
                    NmapService(
                        port=int(service.port),
                        protocol=str(service.protocol),
                        service=service_name,
                        version=_service_version(service),
                        os_match=_os_match(host),
                    )
                )
    except (OSError, RuntimeError, ValueError, AttributeError, TypeError) as error:
        logger.exception("Nmap scan failed for target %s", validated_target)
        raise RuntimeError(f"Nmap scan failed: {error}") from error
    logger.info("Nmap scan completed for %s", validated_target)
    return NmapResult(
        target=validated_target,
        services=services,
        os_detection=os_detection,
        scan_time=time.monotonic() - started_at,
    )
