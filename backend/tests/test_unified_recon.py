import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.scan import ScanRequest
from app.tasks.recon import (
    _merge_recon_subdomains,
    _persist_unified_recon,
    run_unified_recon_task,
)


def _execute_task(
    target: str,
    recon_tools: list[str] | None = None,
    amass_mode: str = "passive",
) -> dict:
    """Run the unified task body, replacing the shared worker loop."""
    with patch("app.tasks.recon._run_async", side_effect=asyncio.run):
        return run_unified_recon_task.run(target, recon_tools, amass_mode)


def test_merge_recon_subdomains_deduplicates_and_marks_sources() -> None:
    merged = _merge_recon_subdomains(
        ["a.example.com", "b.example.com", "A.Example.com."],
        ["b.example.com", "c.example.com"],
    )
    assert merged == [
        {"name": "a.example.com", "sources": ["subfinder"]},
        {"name": "b.example.com", "sources": ["amass", "subfinder"]},
        {"name": "c.example.com", "sources": ["amass"]},
    ]


def test_merge_recon_subdomains_empty_input() -> None:
    assert _merge_recon_subdomains([], []) == []


@pytest.mark.asyncio
async def test_persist_unified_recon_resolves_and_saves() -> None:
    merged = [
        {"name": "a.example.com", "sources": ["subfinder"]},
        {"name": "b.example.com", "sources": ["amass", "subfinder"]},
    ]
    db = AsyncMock()
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False
    counts = {"subdomains": 2, "ip_links": 2, "asn_records": 1}
    amass_result = {
        "subdomains": ["b.example.com"],
        "resolved": {"b.example.com": ["5.6.7.8"]},
        "asn_info": [{"asn_number": 15169, "description": "GOOGLE"}],
    }

    with (
        patch(
            "app.tasks.recon._resolve_batches",
            new_callable=AsyncMock,
            return_value={"a.example.com": ["1.2.3.4"]},
        ),
        patch(
            "app.tasks.recon.crud.save_unified_recon_results",
            new_callable=AsyncMock,
            return_value=counts,
        ) as save,
        patch("app.tasks.recon.AsyncSessionLocal", return_value=db),
    ):
        result = await _persist_unified_recon("example.com", merged, amass_result)

    assert result == {
        "domain": "example.com",
        "total_subdomains": 2,
        "unique_ips": 2,
        "tools_used": ["amass", "subfinder"],
        "asn_info": [{"asn_number": 15169, "description": "GOOGLE"}],
    }
    saved = save.call_args.args[2]
    by_name = {entry["name"]: entry for entry in saved}
    assert by_name["a.example.com"]["ip_addresses"] == ["1.2.3.4"]
    assert by_name["b.example.com"]["ip_addresses"] == ["5.6.7.8"]


def test_unified_recon_invalid_domain_fails() -> None:
    with (
        patch("app.tasks.recon.validate_domain", side_effect=ValueError("bad")),
        patch.object(run_unified_recon_task, "update_state") as update_state,
        pytest.raises(ValueError),
    ):
        _execute_task("not a domain; rm -rf /")

    update_state.assert_called_once_with(state="FAILURE", meta={"error": "bad"})


def test_unified_recon_requires_at_least_one_tool() -> None:
    with (
        patch.object(run_unified_recon_task, "update_state") as update_state,
        pytest.raises(ValueError, match="recon_tools"),
    ):
        _execute_task("example.com", recon_tools=[])

    update_state.assert_called_once_with(
        state="FAILURE", meta={"error": "no recon tools selected"}
    )


def test_unified_recon_dispatches_group_and_merges() -> None:
    subfinder_child = MagicMock()
    subfinder_child.state = "SUCCESS"
    subfinder_child.ready.return_value = True
    subfinder_child.result = ["a.example.com", "shared.example.com"]
    amass_child = MagicMock()
    amass_child.state = "SUCCESS"
    amass_child.ready.return_value = True
    amass_child.result = {
        "subdomains": ["shared.example.com", "b.example.com"],
        "resolved": {"shared.example.com": ["1.2.3.4"]},
        "asn_info": [{"asn_number": 15169}],
    }
    group_result = MagicMock()
    group_result.results = [subfinder_child, amass_child]
    group_result.apply_async.return_value = group_result
    persisted = {
        "domain": "example.com",
        "total_subdomains": 3,
        "unique_ips": 1,
        "tools_used": ["amass", "subfinder"],
        "asn_info": [{"asn_number": 15169}],
    }

    with (
        patch("app.tasks.recon.validate_domain", return_value="example.com"),
        patch("app.tasks.recon.group", return_value=group_result),
        patch(
            "app.tasks.recon._persist_unified_recon",
            new_callable=AsyncMock,
            return_value=persisted,
        ) as persist,
        patch.object(run_unified_recon_task, "update_state"),
        patch("app.tasks.recon._run_async", side_effect=asyncio.run),
        patch("app.tasks.recon.time.sleep"),
    ):
        result = _execute_task(
            "example.com",
            recon_tools=["subfinder", "amass"],
            amass_mode="passive",
        )

    subfinder_child.ready.assert_called()
    amass_child.ready.assert_called()
    assert result["status"] == "success"
    assert result["total_subdomains"] == 3
    assert result["tools_used"] == ["subfinder", "amass"]


def test_scan_request_ip_target_ignores_recon_tools() -> None:
    request = ScanRequest(target="192.168.1.1", recon_tools=["subfinder", "amass"])
    assert request.recon_tools == []


def test_scan_request_amass_scan_type_forces_amass_tool() -> None:
    request = ScanRequest(target="example.com", scan_type="amass")
    assert request.recon_tools == ["amass"]


def test_scan_request_invalid_recon_tool_rejected() -> None:
    with pytest.raises(ValueError, match="recon_tools"):
        ScanRequest(target="example.com", scan_type="recon", recon_tools=[])
