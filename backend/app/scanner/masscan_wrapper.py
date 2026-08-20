import importlib
import json
import logging
import time
from typing import Any

from .models import MasscanResult, ScannedPort
from .validator import validate_ports, validate_target


logger = logging.getLogger(__name__)


def _parse_scan_result(scan_result: Any) -> list[ScannedPort]:
    if isinstance(scan_result, (str, bytes, bytearray)):
        try:
            scan_result = json.loads(scan_result)
        except json.JSONDecodeError as error:
            raise ValueError("Masscan returned invalid JSON output") from error
    ports: list[ScannedPort] = []
    scan_hosts = scan_result.get("scan", {}) if isinstance(scan_result, dict) else {}
    for host_data in scan_hosts.values():
        if isinstance(host_data, list):
            for entry in host_data:
                if not isinstance(entry, dict):
                    continue
                # python-masscan nests actual discoveries under entry["ports"].
                entries = entry.get("ports", [entry])
                if not isinstance(entries, list):
                    continue
                for port_entry in entries:
                    if not isinstance(port_entry, dict):
                        continue
                    if port_entry.get("status", port_entry.get("state")) != "open":
                        continue
                    ports.append(
                        ScannedPort(
                            port=int(port_entry["port"]),
                            protocol=str(port_entry.get("proto", "")),
                            service=str(
                                port_entry.get("service", port_entry.get("name", ""))
                            ),
                        )
                    )
            continue
        for protocol, protocol_data in host_data.items():
            if not isinstance(protocol_data, dict):
                continue
            for port, details in protocol_data.items():
                if not isinstance(details, dict) or details.get("state") != "open":
                    continue
                ports.append(
                    ScannedPort(
                        port=int(port),
                        protocol=str(protocol),
                        service=str(details.get("name", "")),
                    )
                )
    return ports


def run_masscan(target: str, ports: str = "80,443,22,21,8080,3389") -> MasscanResult:
    """Run Masscan through its Python wrapper and normalize the result.

    Args:
        target: IP address, CIDR, or comma-separated target list.
        ports: Numeric port, range, or comma-separated port specification.

    Returns:
        A validated target and list of open ports with elapsed scan time.

    Raises:
        RuntimeError: If the Python wrapper or Masscan executable is unavailable.
        ValueError: If target or ports are invalid.
    """
    validated_target = validate_target(target)
    validated_ports = validate_ports(ports)
    try:
        masscan_module = importlib.import_module("masscan")
        scanner = masscan_module.PortScanner()
    except (ImportError, ModuleNotFoundError) as error:
        logger.exception("python-masscan is not installed")
        raise RuntimeError("python-masscan is required to run Masscan") from error

    started_at = time.monotonic()
    try:
        scanner.scan(validated_target, ports=validated_ports)
        logger.warning("=== MASSCAN RAW OUTPUT ===")
        logger.warning("Full scan_result: %r", scanner.scan_result)
        logger.warning("Type: %s", type(scanner.scan_result))
        parsed_ports = _parse_scan_result(scanner.scan_result)
        result = MasscanResult(
            target=validated_target,
            scanned_ports=parsed_ports,
            scan_time=time.monotonic() - started_at,
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        AttributeError,
        TypeError,
        KeyError,
    ) as error:
        logger.exception("Masscan scan failed for target %s", validated_target)
        raise RuntimeError(f"Masscan scan failed: {error}") from error
    logger.warning("=== MASSCAN PARSED RESULT ===")
    logger.warning("Target IP: %s", validated_target)
    logger.warning("Found ports count: %d", len(result.scanned_ports))
    for port in result.scanned_ports:
        logger.warning("  - Port %d/%s: %s", port.port, port.protocol, port.service)
    logger.info("Masscan scan completed for %s", validated_target)
    return result
