import ipaddress
import re


_PORTS_PATTERN = re.compile(
    r"^(?:[1-9]\d{0,4})(?:-(?:[1-9]\d{0,4}))?"
    r"(?:,(?:[1-9]\d{0,4})(?:-(?:[1-9]\d{0,4}))?)*$"
)
_MAX_TARGET_LENGTH = 4096


def validate_target(target: str) -> str:
    """Validate and normalize an IP, CIDR, or comma-separated target list.

    Args:
        target: IP address, CIDR network, or comma-separated combination.

    Returns:
        A comma-separated string containing validated targets.

    Raises:
        ValueError: If the input is empty or contains an invalid target.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")
    if len(target) > _MAX_TARGET_LENGTH:
        raise ValueError("target is too long")

    targets = [item.strip() for item in target.split(",")]
    if any(not item for item in targets):
        raise ValueError("target list must not contain empty items")

    normalized: list[str] = []
    for item in targets:
        try:
            normalized.append(str(ipaddress.ip_address(item)))
        except ValueError:
            try:
                normalized.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError as error:
                raise ValueError(
                    f"invalid target '{item}': expected an IP address or CIDR"
                ) from error
    return ",".join(normalized)


def validate_ports(ports: str) -> str:
    """Validate a numeric port, range, or comma-separated port list.

    Args:
        ports: Port specification such as ``80`` or ``1-1024,8080``.

    Returns:
        The unchanged validated port specification.

    Raises:
        ValueError: If a port contains non-numeric data or is out of range.
    """
    if not isinstance(ports, str) or not _PORTS_PATTERN.fullmatch(ports):
        raise ValueError("ports must contain numbers or numeric ranges")
    for part in ports.split(","):
        for value in part.split("-"):
            if not 1 <= int(value) <= 65535:
                raise ValueError("port numbers must be between 1 and 65535")
    return ports
