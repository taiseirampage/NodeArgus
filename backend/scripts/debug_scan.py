import argparse
import logging
from pathlib import Path
import sys

import masscan

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.masscan_wrapper import _parse_scan_result
from app.scanner.validator import validate_ports, validate_target


logger = logging.getLogger(__name__)


def main() -> None:
    """Run a diagnostic Masscan and log raw and parsed discoveries."""
    parser = argparse.ArgumentParser(description="Diagnose Masscan parsing")
    parser.add_argument("target", nargs="?", default="92.53.106.219")
    parser.add_argument("--ports", default="80,443,22,21,8080,3389")
    args = parser.parse_args()
    target = validate_target(args.target)
    ports = validate_ports(args.ports)
    scanner = masscan.PortScanner()
    scanner.scan(target, ports=ports)
    logger.warning("=== DEBUG MASSCAN RAW ===")
    logger.warning("Type: %s", type(scanner.scan_result))
    logger.warning("Raw result: %r", scanner.scan_result)
    parsed = _parse_scan_result(scanner.scan_result)
    logger.warning("=== DEBUG MASSCAN PARSED ===")
    logger.warning("Parsed ports: %d", len(parsed))
    for port in parsed:
        logger.warning("Port %d/%s service=%s", port.port, port.protocol, port.service)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
