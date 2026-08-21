import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.scanner.amass_wrapper import (
    PASSIVE_TIMEOUT_SECONDS,
    AmassError,
    _build_command,
    _parse_records,
    run_amass,
)


def _make_stream(data: str) -> MagicMock:
    """Return a stream whose ``read`` yields the data once, then EOF."""
    stream = MagicMock()
    reader = io.BytesIO(data.encode())
    stream.read = AsyncMock(side_effect=[reader.read(4096), b""])
    return stream


def _exec_result(returncode: int, stdout: str) -> SimpleNamespace:
    process = SimpleNamespace()
    process.returncode = returncode
    process.stdout = _make_stream(stdout)
    process.stderr = _make_stream("")
    process.kill = MagicMock()
    process.communicate = AsyncMock(return_value=(b"", b""))
    return process


def test_parse_records_extracts_subdomains_ips_and_asn() -> None:
    output = (
        "example.com (FQDN) --> ns_record --> hera.ns.cloudflare.com (FQDN)\n"
        "www.example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)\n"
        "www.example.com (FQDN) --> aaaa_record --> 2606:2800:220:1::1 (IPAddress)\n"
        "hera.ns.cloudflare.com (FQDN) --> a_record --> 173.245.58.162 (IPAddress)\n"
        "93.184.216.0/24 (Netblock) --> contains --> 93.184.216.34 (IPAddress)\n"
        "15169 (ASN) --> announces --> 93.184.216.0/24 (Netblock)\n"
        "15169 (ASN) --> managed_by --> GOOGLE, America/New_York (RIROrganization)\n"
    )
    result = _parse_records(output, "example.com")
    assert result["subdomains"] == ["www.example.com"]
    assert result["resolved"] == {
        "www.example.com": ["2606:2800:220:1::1", "93.184.216.34"]
    }
    assert result["ip_addresses"] == [
        "173.245.58.162",
        "2606:2800:220:1::1",
        "93.184.216.34",
    ]
    assert result["asn_info"] == [
        {
            "asn_number": 15169,
            "cidr": "93.184.216.0/24",
            "description": "GOOGLE, America/New_York",
        }
    ]


def test_parse_records_filters_out_of_scope_names() -> None:
    output = (
        "www.example.com (FQDN) --> a_record --> 93.184.216.34 (IPAddress)\n"
        "other.org (FQDN) --> ns_record --> ns1.other.org (FQDN)\n"
    )
    result = _parse_records(output, "example.com")
    assert result["subdomains"] == ["www.example.com"]


def test_parse_records_ignores_malformed_lines() -> None:
    output = (
        "93.184.216.0/24 (Netblock) --> contains --> 93.184.216.34 (IPAddress)\n"
        "not a valid relation\n"
    )
    result = _parse_records(output, "example.com")
    assert result["ip_addresses"] == ["93.184.216.34"]


def test_parse_records_returns_empty_structures_for_empty_input() -> None:
    result = _parse_records("", "example.com")
    assert result == {
        "subdomains": [],
        "resolved": {},
        "asn_info": [],
        "ip_addresses": [],
    }


def test_build_command_passive_is_shell_safe() -> None:
    command = _build_command("example.com", "passive")
    assert command[0] == "amass"
    assert command[1] == "enum"
    assert "-passive" in command
    assert "-d" in command
    assert "example.com" in command
    assert all(not isinstance(arg, str) or ";" not in arg for arg in command)


@patch("app.scanner.amass_wrapper.settings")
def test_build_command_active_uses_wordlist(mock_settings) -> None:
    mock_settings.AMASS_WORDLIST_PATH = "/usr/share/wordlists/amass/list.txt"
    mock_settings.AMASS_CONF_PATH = "/root/.config/amass/config.yaml"
    with patch("app.scanner.amass_wrapper.Path.exists", return_value=True):
        command = _build_command("example.com", "active")
    assert "-brute" in command
    assert "-w" in command
    assert "-dns-qps" in command
    assert mock_settings.AMASS_WORDLIST_PATH in command


@patch("app.scanner.amass_wrapper.settings")
def test_build_command_active_raises_when_wordlist_missing(mock_settings) -> None:
    mock_settings.AMASS_WORDLIST_PATH = "/nonexistent/list.txt"
    with patch("app.scanner.amass_wrapper.Path.exists", return_value=False):
        with pytest.raises(AmassError, match="wordlist"):
            _build_command("example.com", "active")


@patch("app.scanner.amass_wrapper.settings")
def test_run_amass_rejects_invalid_domain(mock_settings) -> None:
    mock_settings.ALLOW_ACTIVE_RECON = False
    with pytest.raises(ValueError):
        asyncio.run(run_amass("not a domain; rm -rf /"))


@patch("app.scanner.amass_wrapper._has_active_recon_permission", return_value=False)
def test_run_amass_active_disabled_raises(mock_permission) -> None:
    with pytest.raises(AmassError, match="disabled"):
        asyncio.run(run_amass("example.com", mode="active"))


@patch("app.scanner.amass_wrapper.settings")
def test_run_amass_parses_stdout(mock_settings) -> None:
    mock_settings.ALLOW_ACTIVE_RECON = False
    mock_settings.AMASS_CONF_PATH = "/root/.config/amass/config.yaml"
    stdout = (
        "www.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)\n"
        "1.2.3.0/24 (Netblock) --> contains --> 1.2.3.4 (IPAddress)\n"
        "15169 (ASN) --> announces --> 1.2.3.0/24 (Netblock)\n"
    )
    process = _exec_result(0, stdout)
    with patch(
        "app.scanner.amass_wrapper.asyncio.create_subprocess_exec",
        new_callable=AsyncMock,
        return_value=process,
    ) as exec_mock:
        result = asyncio.run(run_amass("example.com"))

    assert result["subdomains"] == ["www.example.com"]
    assert result["ip_addresses"] == ["1.2.3.4"]
    assert result["asn_info"][0]["asn_number"] == 15169
    assert "-passive" in exec_mock.call_args.args


@patch("app.scanner.amass_wrapper.settings")
def test_run_amass_raises_on_nonzero_exit(mock_settings) -> None:
    mock_settings.ALLOW_ACTIVE_RECON = False
    mock_settings.AMASS_CONF_PATH = "/root/.config/amass/config.yaml"
    process = _exec_result(1, "")
    with (
        patch(
            "app.scanner.amass_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=process,
        ),
        pytest.raises(AmassError, match="exit code 1"),
    ):
        asyncio.run(run_amass("example.com"))


@patch("app.scanner.amass_wrapper.settings")
def test_run_amass_raises_when_binary_missing(mock_settings) -> None:
    mock_settings.ALLOW_ACTIVE_RECON = False
    mock_settings.AMASS_CONF_PATH = "/root/.config/amass/config.yaml"
    with (
        patch(
            "app.scanner.amass_wrapper.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            side_effect=FileNotFoundError("amass"),
        ),
        pytest.raises(AmassError, match="not installed"),
    ):
        asyncio.run(run_amass("example.com"))


@patch("app.scanner.amass_wrapper.settings")
@patch("app.scanner.amass_wrapper.asyncio.wait_for")
def test_run_amass_applies_timeout(mock_wait_for, mock_settings) -> None:
    mock_settings.ALLOW_ACTIVE_RECON = False
    mock_settings.AMASS_CONF_PATH = "/root/.config/amass/config.yaml"
    mock_wait_for.side_effect = asyncio.TimeoutError()
    with pytest.raises(AmassError, match="timed out"):
        asyncio.run(run_amass("example.com"))
    assert PASSIVE_TIMEOUT_SECONDS == 180
