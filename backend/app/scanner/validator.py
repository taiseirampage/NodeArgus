import ipaddress
import re
from urllib.parse import urlsplit


_PORTS_PATTERN = re.compile(
    r"^(?:[1-9]\d{0,4})(?:-(?:[1-9]\d{0,4}))?"
    r"(?:,(?:[1-9]\d{0,4})(?:-(?:[1-9]\d{0,4}))?)*$"
)
_MAX_TARGET_LENGTH = 4096
_MAX_DOMAIN_LENGTH = 253
_MAX_WEB_TARGET_LENGTH = 2048
# Strict FQDN: letters, digits, hyphens and dots only; at least one dot; each
# label starts/ends with an alphanumeric; no leading/trailing dot or space.
_FQDN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+"
    r"[a-zA-Z]{2,63}$"
)
_INJECTION_CHARS = frozenset(";|&$` \t\r\n\"'<>()[]{}*?~")


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


def validate_domain(domain: str) -> str:
    """Validate and normalize a single FQDN for passive recon.

    Rejects shell metacharacters and control characters so a caller can pass the
    value to Subfinder as a single argv element without command injection risk.

    Args:
        domain: A fully qualified domain name such as ``example.com``.

    Returns:
        The lowercased, normalized FQDN.

    Raises:
        ValueError: If the domain is empty, contains whitespace, shell
            characters, an invalid label layout, or is too long.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")
    if any(char in _INJECTION_CHARS for char in domain):
        raise ValueError("domain contains forbidden characters")
    value = domain.strip().rstrip(".").lower()
    if len(value) > _MAX_DOMAIN_LENGTH:
        raise ValueError("domain is too long")
    if not _FQDN_PATTERN.fullmatch(value):
        raise ValueError(
            "invalid domain: expected a fully qualified domain name (e.g. example.com)"
        )
    return value


def _validate_authority_host(host: str) -> str:
    """Return the validated IP or hostname part of a URL authority."""
    host = host.rstrip(".")
    if not host:
        raise ValueError("invalid web target: empty host")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        port = int(host.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return validate_domain(host)
    if not 1 <= port <= 65535:
        raise ValueError("invalid web target: port out of range")
    return validate_domain(host.rsplit(":", 1)[0])


def _validate_web_port(port_part: str) -> str:
    if not port_part.isdigit() or not 1 <= int(port_part) <= 65535:
        raise ValueError("invalid web target: port out of range")
    return port_part


def validate_web_target(target: str) -> str:
    """Validate an httpx/katana input: an http(s) URL or a bare hostname/IP.

    Unlike ``validate_target`` this permits ``scheme://host[:port]`` while still
    rejecting shell metacharacters, control characters, and any scheme other
    than ``http``/``https`` so the value stays safe as a single argv element.

    Args:
        target: An http/https URL or a bare validated hostname/IP.

    Returns:
        The normalized target string.

    Raises:
        ValueError: If the target is empty, too long, contains forbidden
            characters, uses a non-HTTP scheme, or has an invalid host/port.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target must be a non-empty string")
    if len(target) > _MAX_WEB_TARGET_LENGTH:
        raise ValueError("target is too long")
    if any(char in _INJECTION_CHARS for char in target):
        raise ValueError("target contains forbidden characters")

    value = target.strip()
    if "://" not in value:
        return _validate_authority_host(value)

    scheme, _, rest = value.partition("://")
    if scheme.lower() not in {"http", "https"}:
        raise ValueError("only http/https URLs are allowed")
    authority = rest.split("/", 1)[0]
    host, separator, port = authority.rpartition(":")
    if separator and port and host:
        validated_host = _validate_authority_host(host)
        validated_port = _validate_web_port(port)
        return f"{scheme.lower()}://{validated_host}:{validated_port}"
    return f"{scheme.lower()}://{_validate_authority_host(authority)}"


def is_valid_web_url(value: str) -> bool:
    """Return True when ``value`` is a full ``http(s)://`` URL with a hostname."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
