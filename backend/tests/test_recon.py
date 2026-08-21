import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.scanner.subfinder_wrapper import SubfinderError
from app.tasks.recon import _enrich_with_ips, run_recon_task


def _execute_task(target: str) -> dict:
    """Run the recon task body, replacing the shared worker loop with a fresh one.

    ``run_recon_task`` delegates to the module-level ``_run_async`` which manages
    a process-wide event loop. In tests we substitute it with ``asyncio.run`` so
    each call runs deterministically on its own loop.
    """
    with patch("app.tasks.recon._run_async", side_effect=asyncio.run):
        return run_recon_task.run(target)


def test_run_recon_task_enriches_and_saves() -> None:
    subfinder_records = [
        {"host": "a.example.com", "source": "crtsh"},
        {"host": "b.example.com", "source": "hackertarget"},
    ]
    enriched = [
        {"name": "a.example.com", "source": "crtsh", "ip_addresses": ["1.2.3.4"]},
        {"name": "b.example.com", "source": "hackertarget", "ip_addresses": []},
    ]
    db = AsyncMock()
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False
    counts = {"domains": 1, "subdomains": 2, "links": 1}

    with (
        patch(
            "app.tasks.recon.run_subfinder",
            new_callable=AsyncMock,
            return_value=subfinder_records,
        ) as subfinder,
        patch(
            "app.tasks.recon._enrich_with_ips",
            new_callable=AsyncMock,
            return_value=enriched,
        ) as enrich,
        patch(
            "app.tasks.recon.crud.save_recon_results",
            new_callable=AsyncMock,
            return_value=counts,
        ) as save,
        patch("app.tasks.recon.AsyncSessionLocal", return_value=db),
    ):
        result = _execute_task("example.com")

    subfinder.assert_called_once_with("example.com")
    enrich.assert_called_once_with(subfinder_records)
    save.assert_called_once_with(db, "example.com", enriched)
    assert result == {"domain": "example.com", **counts}


def test_run_recon_task_returns_empty_when_no_subdomains() -> None:
    with patch(
        "app.tasks.recon.run_subfinder",
        new_callable=AsyncMock,
        return_value=[],
    ):
        result = _execute_task("example.com")

    assert result == {"domain": "example.com", "subdomains": 0, "links": 0}


def test_run_recon_task_marks_subfinder_failure() -> None:
    with (
        patch(
            "app.tasks.recon.run_subfinder",
            new_callable=AsyncMock,
            side_effect=SubfinderError("subfinder binary is not installed"),
        ),
        patch.object(run_recon_task, "update_state") as update_state,
        pytest.raises(SubfinderError),
    ):
        _execute_task("example.com")

    update_state.assert_called_once_with(
        state="FAILURE", meta={"error": "subfinder binary is not installed"}
    )


@pytest.mark.asyncio
async def test_enrich_with_ips_attaches_resolved_addresses() -> None:
    records = [
        {"host": "a.example.com", "source": "crtsh"},
        {"host": "b.example.com", "source": "hackertarget"},
    ]
    with patch(
        "app.tasks.recon._resolve_batches",
        new_callable=AsyncMock,
        return_value={"a.example.com": ["1.2.3.4", "5.6.7.8"], "b.example.com": []},
    ) as resolve:
        enriched = await _enrich_with_ips(records)

    resolve.assert_called_once_with(["a.example.com", "b.example.com"])
    by_host = {entry["name"]: entry for entry in enriched}
    assert by_host["a.example.com"]["ip_addresses"] == ["1.2.3.4", "5.6.7.8"]
    assert by_host["b.example.com"]["ip_addresses"] == []
