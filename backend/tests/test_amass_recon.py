import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.amass_wrapper import AmassError
from app.tasks.amass_recon import run_amass_task


def _execute_task(target: str, mode: str = "passive") -> dict:
    with patch("app.tasks.amass_recon._run_async", side_effect=asyncio.run):
        return run_amass_task.run(target, mode)


def test_run_amass_task_saves_and_returns_counts() -> None:
    amass_result = {
        "subdomains": ["a.example.com", "b.example.com"],
        "resolved": {
            "a.example.com": ["1.2.3.4"],
            "b.example.com": ["5.6.7.8"],
        },
        "asn_info": [{"asn_number": 15169}],
        "ip_addresses": ["1.2.3.4", "5.6.7.8"],
    }
    db = AsyncMock()
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False
    counts = {"subdomains": 2, "ip_links": 2, "asn_records": 1}

    with (
        patch(
            "app.tasks.amass_recon.run_amass",
            new_callable=AsyncMock,
            return_value=amass_result,
        ) as amass,
        patch(
            "app.tasks.amass_recon.crud.save_amass_results",
            new_callable=AsyncMock,
            return_value=counts,
        ) as save,
        patch("app.tasks.amass_recon.AsyncSessionLocal", return_value=db),
        patch("app.tasks.amass_recon.open_geo_service", return_value=None) as geo,
    ):
        result = _execute_task("example.com", "passive")

    amass.assert_called_once_with("example.com", "passive")
    save.assert_called_once_with(db, "example.com", amass_result, None)
    geo.assert_called_once()
    assert result == {
        "domain": "example.com",
        "subdomains": 2,
        "ip_links": 2,
        "asn_records": 1,
    }


def test_run_amass_task_returns_empty_when_no_findings() -> None:
    amass_result = {
        "subdomains": [],
        "resolved": {},
        "asn_info": [],
        "ip_addresses": [],
    }
    with patch(
        "app.tasks.amass_recon.run_amass",
        new_callable=AsyncMock,
        return_value=amass_result,
    ) as amass:
        result = _execute_task("example.com")

    amass.assert_called_once_with("example.com", "passive")
    assert result == {
        "domain": "example.com",
        "subdomains": 0,
        "asn_records": 0,
        "ip_links": 0,
    }


def test_run_amass_task_marks_failure_on_error() -> None:
    with (
        patch(
            "app.tasks.amass_recon.run_amass",
            new_callable=AsyncMock,
            side_effect=AmassError("amass binary is not installed"),
        ),
        pytest.raises(AmassError),
    ):
        _execute_task("example.com")


def test_run_amass_task_rejects_invalid_mode() -> None:
    with pytest.raises(ValueError, match="mode"):
        _execute_task("example.com", "fast")
