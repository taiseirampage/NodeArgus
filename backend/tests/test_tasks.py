from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest

from app.api.v1.endpoints.scan import (
    ScanRequest,
    celery_app,
    create_scan,
    get_scan_status,
)
from app.geo.models import GeoLocation
from app.scanner.models import MasscanResult, NmapResult, ScannedPort
from app.tasks import _run_async, run_scan_task


@pytest.mark.asyncio
async def test_scan_endpoint_enqueues_task() -> None:
    task = SimpleNamespace(id="celery-task-123")
    with patch("app.api.v1.endpoints.scan.run_scan_task") as task_proxy:
        task_proxy.delay.return_value = task
        response = await create_scan(ScanRequest(target="192.168.1.1"))

    task_proxy.delay.assert_called_once_with("192.168.1.1")
    assert response.model_dump() == {
        "task_id": "celery-task-123",
        "status": "queued",
        "scan_type": "active",
    }


@pytest.mark.asyncio
async def test_scan_endpoint_dispatches_recon_task() -> None:
    task = SimpleNamespace(id="recon-task-1")
    with patch("app.api.v1.endpoints.scan.run_recon_task") as task_proxy:
        task_proxy.delay.return_value = task
        response = await create_scan(
            ScanRequest(target="Example.COM", scan_type="recon")
        )

    task_proxy.delay.assert_called_once_with("example.com")
    assert response.model_dump() == {
        "task_id": "recon-task-1",
        "status": "queued",
        "scan_type": "recon",
    }


@pytest.mark.asyncio
async def test_scan_endpoint_dispatches_full_scan_task() -> None:
    task = SimpleNamespace(id="full-task-1")
    with patch("app.api.v1.endpoints.scan.run_full_scan_task") as task_proxy:
        task_proxy.delay.return_value = task
        response = await create_scan(
            ScanRequest(target="hackthebox.com", scan_type="full")
        )

    task_proxy.delay.assert_called_once_with("hackthebox.com")
    assert response.model_dump() == {
        "task_id": "full-task-1",
        "status": "queued",
        "scan_type": "full",
    }


def test_scan_request_rejects_injectable_domain_for_recon() -> None:
    with pytest.raises(ValueError):
        ScanRequest(target="example.com; rm -rf /", scan_type="recon")


def test_scan_request_rejects_injectable_ip_for_active() -> None:
    with pytest.raises(ValueError):
        ScanRequest(target="192.168.1.1 && whoami", scan_type="active")


@pytest.mark.parametrize(
    ("state", "result", "info", "expected_status"),
    [
        ("PENDING", None, None, "pending"),
        ("SUCCESS", {"status": "success", "ports_found": 3}, None, "success"),
        ("FAILURE", None, "scanner failed", "failed"),
    ],
)
def test_get_scan_status(
    state: str,
    result: dict[str, object] | None,
    info: str | None,
    expected_status: str,
) -> None:
    task = MagicMock(state=state, result=result, info=info)
    with patch(
        "app.api.v1.endpoints.scan.AsyncResult", return_value=task
    ) as result_class:
        response = get_scan_status("celery-task-123")

    result_class.assert_called_once_with("celery-task-123", app=celery_app)
    assert response.task_id == "celery-task-123"
    assert response.status == expected_status
    if state == "SUCCESS":
        assert response.result == result
    else:
        assert response.result is None
    if state == "FAILURE":
        assert response.error == info
    else:
        assert response.error is None


def test_run_scan_task_success() -> None:
    masscan_result = MasscanResult(
        target="8.8.8.8",
        scanned_ports=[ScannedPort(port=80, protocol="tcp", service="http")],
        scan_time=0.1,
    )
    nmap_result = NmapResult(
        target="8.8.8.8", services=[], os_detection="Linux", scan_time=0.1
    )
    geo = GeoLocation(ip="8.8.8.8", country_code="US")
    geo_service = MagicMock()
    geo_service.__enter__.return_value = geo_service
    geo_service.lookup.return_value = geo

    with (
        patch("app.tasks.scan.validate_target", return_value="8.8.8.8") as validate,
        patch("app.tasks.scan.run_masscan", return_value=masscan_result) as masscan,
        patch("app.tasks.scan.run_nmap", return_value=nmap_result) as nmap,
        patch("app.tasks.scan.GeoIPService", return_value=geo_service) as geo_class,
        patch("app.tasks.scan._save_scan_result", new_callable=MagicMock) as save,
        patch("app.tasks.scan._run_async") as run_async,
    ):
        save.return_value = None
        result = run_scan_task.run("8.8.8.8")

    validate.assert_called_once_with("8.8.8.8")
    masscan.assert_called_once_with("8.8.8.8")
    nmap.assert_called_once_with("8.8.8.8", ports="80")
    geo_class.assert_called_once()
    geo_service.lookup.assert_called_once_with("8.8.8.8")
    saved_result = save.call_args.args[0]
    assert saved_result.services[0].port == 80
    save.assert_called_once_with(saved_result, geo)
    run_async.assert_called_once_with(None)
    assert result == {"status": "success", "ports_found": 1}


def test_run_async_reuses_event_loop() -> None:
    async def value(number: int) -> int:
        return number

    assert _run_async(value(1)) == 1
    first_loop = _run_async.__globals__["_worker_loop"]
    assert _run_async(value(2)) == 2
    assert _run_async.__globals__["_worker_loop"] is first_loop


def test_run_scan_task_persists_each_target_in_a_list() -> None:
    masscan_result = MasscanResult(
        target="192.168.1.10,192.168.1.20,192.168.1.100",
        scanned_ports=[ScannedPort(port=80, protocol="tcp", service="http")],
        scan_time=0.1,
    )
    nmap_result = NmapResult(
        target="192.168.1.10", services=[], os_detection="Linux", scan_time=0.1
    )
    geo = GeoLocation(ip="192.168.1.10")
    geo_service = MagicMock()
    geo_service.__enter__.return_value = geo_service
    geo_service.lookup.return_value = geo

    with (
        patch(
            "app.tasks.scan.validate_target",
            return_value="192.168.1.10,192.168.1.20,192.168.1.100",
        ),
        patch("app.tasks.scan.run_masscan", return_value=masscan_result),
        patch("app.tasks.scan.run_nmap", return_value=nmap_result) as nmap,
        patch("app.tasks.scan.GeoIPService", return_value=geo_service),
        patch("app.tasks.scan._save_scan_result", new_callable=MagicMock) as save,
        patch("app.tasks.scan._run_async") as run_async,
    ):
        result = run_scan_task.run(masscan_result.target)

    assert nmap.call_args_list == [
        call("192.168.1.10", ports="80"),
        call("192.168.1.20", ports="80"),
        call("192.168.1.100", ports="80"),
    ]
    assert geo_service.lookup.call_args_list == [
        call("192.168.1.10"),
        call("192.168.1.20"),
        call("192.168.1.100"),
    ]
    assert save.call_count == 3
    assert run_async.call_count == 3
    assert result == {"status": "success", "ports_found": 3}


def test_run_scan_task_marks_invalid_target_as_failure() -> None:
    with (
        patch(
            "app.tasks.scan.validate_target",
            side_effect=ValueError("invalid target"),
        ),
        patch.object(run_scan_task, "update_state") as update_state,
        pytest.raises(ValueError, match="invalid target"),
    ):
        run_scan_task.run("192.168.1.1; rm -rf /")

    update_state.assert_called_once_with(
        state="FAILURE", meta={"error": "invalid target"}
    )
