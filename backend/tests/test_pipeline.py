from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.tasks.pipeline import _group_active_scans, run_full_scan_task


class FakeGroup:
    def __init__(self) -> None:
        self.id = "group-123"

    def apply_async(self) -> "FakeGroup":
        return self


def test_group_active_scans_builds_signatures_for_each_ip() -> None:
    workflow = _group_active_scans(["1.2.3.4", "5.6.7.8"])
    signatures = list(workflow.tasks)
    assert len(signatures) == 2
    assert signatures[0].args == ("1.2.3.4",)
    assert signatures[1].args == ("5.6.7.8",)


def test_run_full_scan_task_runs_recon_then_dispatches_group() -> None:
    fake_group = FakeGroup()

    with (
        patch(
            "app.tasks.pipeline.validate_domain",
            return_value="hackthebox.com",
        ) as validate,
        patch("app.tasks.pipeline.run_recon_task") as recon,
        patch("app.tasks.pipeline._collect_domain_ips") as collect,
        patch(
            "app.tasks.pipeline._group_active_scans", return_value=fake_group
        ) as group_builder,
        patch("app.tasks.pipeline._run_async") as run_async,
    ):
        recon.run.return_value = {
            "domain": "hackthebox.com",
            "subdomains": 3,
            "links": 5,
        }
        collect.return_value = ["1.2.3.4", "5.6.7.8"]
        run_async.return_value = ["1.2.3.4", "5.6.7.8"]

        result = run_full_scan_task.run("hackthebox.com")

    validate.assert_called_once_with("hackthebox.com")
    recon.run.assert_called_once_with("hackthebox.com")
    group_builder.assert_called_once_with(["1.2.3.4", "5.6.7.8"])
    assert result == {
        "status": "success",
        "domain": "hackthebox.com",
        "subdomains_found": 3,
        "ips_to_scan": 2,
    }


def test_run_full_scan_task_skips_phase_when_no_ips() -> None:
    with (
        patch("app.tasks.pipeline.validate_domain", return_value="example.com"),
        patch("app.tasks.pipeline.run_recon_task") as recon,
        patch("app.tasks.pipeline._collect_domain_ips") as collect,
        patch("app.tasks.pipeline._run_async") as run_async,
        patch("app.tasks.pipeline._group_active_scans") as group_builder,
    ):
        recon.run.return_value = {"domain": "example.com", "subdomains": 0, "links": 0}
        run_async.return_value = []

        result = run_full_scan_task.run("example.com")

    group_builder.assert_not_called()
    assert result["ips_to_scan"] == 0
    assert "No subdomains resolved" in result["message"]


def test_run_full_scan_task_marks_failure_on_error() -> None:
    with (
        patch(
            "app.tasks.pipeline.validate_domain",
            side_effect=ValueError("invalid domain"),
        ),
        patch.object(run_full_scan_task, "update_state") as update_state,
        pytest.raises(ValueError, match="invalid domain"),
    ):
        run_full_scan_task.run("not a domain")

    update_state.assert_called_once_with(
        state="FAILURE", meta={"error": "invalid domain"}
    )
