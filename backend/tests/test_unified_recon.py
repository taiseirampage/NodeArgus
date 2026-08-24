import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.scan import ScanRequest
from app.tasks.recon import (
    _merge_recon_subdomains,
    _persist_unified_recon,
    _recon_progress,
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


def test_recon_progress_skips_when_request_id_missing() -> None:
    task = MagicMock()
    task.request.id = None
    task.update_state = MagicMock(side_effect=ValueError("task_id must not be empty"))
    _recon_progress(task, {"subfinder": "running"})
    task.update_state.assert_not_called()


def test_recon_progress_writes_when_request_id_present() -> None:
    task = MagicMock()
    task.request.id = "task-123"
    task.update_state = MagicMock()
    _recon_progress(task, {"subfinder": "running"})
    task.update_state.assert_called_once_with(
        state="PROGRESS", meta={"progress": {"subfinder": "running"}}
    )


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


@pytest.mark.asyncio
async def test_persist_unified_recon_saves_asn_when_no_subdomains() -> None:
    db = AsyncMock()
    db.__aenter__.return_value = db
    db.__aexit__.return_value = False
    counts = {"subdomains": 0, "ip_links": 0, "asn_records": 1}
    amass_result = {
        "subdomains": [],
        "resolved": {},
        "asn_info": [{"asn_number": 49981, "description": "WORLDSTREAM"}],
        "ip_addresses": ["89.39.104.183"],
    }

    with (
        patch(
            "app.tasks.recon._resolve_batches",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "app.tasks.recon.crud.save_unified_recon_results",
            new_callable=AsyncMock,
            return_value=counts,
        ) as save,
        patch("app.tasks.recon.AsyncSessionLocal", return_value=db),
    ):
        result = await _persist_unified_recon("p.porno365.broker", [], amass_result)

    assert result == {
        "domain": "p.porno365.broker",
        "total_subdomains": 0,
        "unique_ips": 1,
        "tools_used": [],
        "asn_info": [{"asn_number": 49981, "description": "WORLDSTREAM"}],
    }
    save.assert_called_once()
    assert save.call_args.args[3] == [
        {"asn_number": 49981, "description": "WORLDSTREAM"}
    ]


def test_unified_recon_invalid_domain_fails() -> None:
    with (
        patch("app.tasks.recon.validate_domain", side_effect=ValueError("bad")),
        pytest.raises(ValueError, match="bad"),
    ):
        _execute_task("not a domain; rm -rf /")


def test_unified_recon_requires_at_least_one_tool() -> None:
    with pytest.raises(ValueError, match="recon_tools"):
        _execute_task("example.com", recon_tools=[])


def test_unified_recon_degrades_when_amass_disabled() -> None:
    subfinder_child = MagicMock()
    subfinder_child.state = "SUCCESS"
    subfinder_child.ready.return_value = True
    subfinder_child.result = ["a.example.com"]
    amass_child = MagicMock()
    amass_child.state = "SUCCESS"
    amass_child.ready.return_value = True
    amass_child.result = {"error": "active recon is disabled"}
    group_result = MagicMock()
    group_result.results = [subfinder_child, amass_child]
    group_result.apply_async.return_value = group_result
    persisted = {
        "domain": "example.com",
        "total_subdomains": 1,
        "unique_ips": 1,
        "tools_used": ["amass", "subfinder"],
        "asn_info": [],
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
        patch("app.tasks.recon.run_web_recon_task") as web_recon,
    ):
        result = _execute_task(
            "example.com",
            recon_tools=["subfinder", "amass"],
            amass_mode="active",
        )

    assert result["status"] == "partial"
    assert persist.call_args.args[1][0]["name"] == "a.example.com"
    assert result["tool_errors"] == {"amass": "active recon is disabled"}
    web_recon.delay.assert_called_once_with("example.com")


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
        patch("app.tasks.recon.run_web_recon_task") as web_recon,
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
    web_recon.delay.assert_called_once_with("example.com")
    assert result["web_recon_dispatched"] is True


def test_unified_recon_empty_subfinder_is_not_an_error() -> None:
    subfinder_child = MagicMock()
    subfinder_child.state = "SUCCESS"
    subfinder_child.ready.return_value = True
    subfinder_child.result = []
    amass_child = MagicMock()
    amass_child.state = "SUCCESS"
    amass_child.ready.return_value = True
    amass_child.result = {"subdomains": [], "resolved": {}, "asn_info": []}
    group_result = MagicMock()
    group_result.results = [subfinder_child, amass_child]
    group_result.apply_async.return_value = group_result
    persisted = {
        "domain": "p.porno365.broker",
        "total_subdomains": 0,
        "unique_ips": 0,
        "tools_used": ["subfinder", "amass"],
        "asn_info": [],
    }

    with (
        patch("app.tasks.recon.validate_domain", return_value="p.porno365.broker"),
        patch("app.tasks.recon.group", return_value=group_result),
        patch(
            "app.tasks.recon._persist_unified_recon",
            new_callable=AsyncMock,
            return_value=persisted,
        ),
        patch.object(run_unified_recon_task, "update_state"),
        patch("app.tasks.recon._run_async", side_effect=asyncio.run),
        patch("app.tasks.recon.time.sleep"),
        patch("app.tasks.recon.run_web_recon_task") as web_recon,
    ):
        result = _execute_task(
            "p.porno365.broker",
            recon_tools=["subfinder", "amass"],
            amass_mode="passive",
        )

    assert result["status"] == "success"
    assert "tool_errors" not in result
    web_recon.delay.assert_called_once_with("p.porno365.broker")


def test_scan_request_ip_target_ignores_recon_tools() -> None:
    request = ScanRequest(target="192.168.1.1", recon_tools=["subfinder", "amass"])
    assert request.recon_tools == []


def test_scan_request_amass_scan_type_forces_amass_tool() -> None:
    request = ScanRequest(target="example.com", scan_type="amass")
    assert request.recon_tools == ["amass"]


def test_scan_request_invalid_recon_tool_rejected() -> None:
    with pytest.raises(ValueError, match="recon_tools"):
        ScanRequest(target="example.com", scan_type="recon", recon_tools=[])
