from unittest.mock import MagicMock, patch

import pytest

from app.tasks.pipeline import (
    _group_active_scans,
    dispatch_web_recon_task,
    run_full_scan_task,
)


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


def test_run_full_scan_task_runs_recon_then_builds_chord() -> None:
    fake_group = FakeGroup()
    fake_chord = MagicMock()
    fake_chord.return_value.id = "chord-1"

    with (
        patch(
            "app.tasks.pipeline.validate_domain",
            return_value="hackthebox.com",
        ) as validate,
        patch("app.tasks.pipeline.run_unified_recon_task") as recon,
        patch("app.tasks.pipeline._collect_domain_ips") as collect,
        patch(
            "app.tasks.pipeline._group_active_scans", return_value=fake_group
        ) as group_builder,
        patch("app.tasks.pipeline.chord", return_value=fake_chord) as chord_builder,
        patch("app.tasks.pipeline._run_async") as run_async,
    ):
        recon.run.return_value = {
            "domain": "hackthebox.com",
            "total_subdomains": 3,
            "unique_ips": 2,
            "tools_used": ["subfinder", "amass"],
        }
        collect.return_value = ["1.2.3.4", "5.6.7.8"]
        run_async.return_value = ["1.2.3.4", "5.6.7.8"]

        result = run_full_scan_task.run(
            "hackthebox.com", ["subfinder", "amass"], "passive"
        )

    validate.assert_called_once_with("hackthebox.com")
    recon.run.assert_called_once_with(
        "hackthebox.com", ["subfinder", "amass"], "passive"
    )
    group_builder.assert_called_once_with(["1.2.3.4", "5.6.7.8"])
    chord_builder.assert_called_once_with(fake_group)
    # The chord body is the web recon dispatch task bound to the domain,
    # i.e. dispatched through chord(header)(body).
    assert fake_chord.call_args.args[0].args == ("hackthebox.com",)
    assert result == {
        "status": "success",
        "domain": "hackthebox.com",
        "subdomains_found": 3,
        "ips_to_scan": 2,
    }


def test_run_full_scan_task_skips_phase_when_no_ips() -> None:
    with (
        patch("app.tasks.pipeline.validate_domain", return_value="example.com"),
        patch("app.tasks.pipeline.run_unified_recon_task") as recon,
        patch("app.tasks.pipeline._collect_domain_ips") as collect,
        patch("app.tasks.pipeline._run_async") as run_async,
        patch("app.tasks.pipeline._group_active_scans") as group_builder,
        patch("app.tasks.pipeline.chord"),
    ):
        recon.run.return_value = {
            "domain": "example.com",
            "total_subdomains": 0,
            "unique_ips": 0,
        }
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
        pytest.raises(ValueError, match="invalid domain"),
    ):
        run_full_scan_task.run("not a domain")


def test_dispatch_web_recon_task_enqueues_ip_web_recon_only() -> None:
    fake_group = MagicMock()
    fake_group.apply_async.return_value = fake_group

    with (
        patch("app.tasks.pipeline._run_async") as run_async,
        patch("app.tasks.pipeline.group", return_value=fake_group) as group_mock,
        patch("app.tasks.pipeline.run_web_recon_task") as web_recon,
    ):
        run_async.return_value = ["1.2.3.4", "5.6.7.8"]
        result = dispatch_web_recon_task.run([], "example.com")

    group_mock.assert_called_once()
    fake_group.apply_async.assert_called_once_with()
    web_recon.delay.assert_not_called()
    assert result == {
        "status": "success",
        "domain": "example.com",
        "web_recon_targets": 2,
    }


def test_dispatch_web_recon_task_skips_when_no_web_ports() -> None:
    with (
        patch("app.tasks.pipeline._run_async") as run_async,
        patch("app.tasks.pipeline.group") as group_mock,
        patch("app.tasks.pipeline.run_web_recon_task") as web_recon,
    ):
        run_async.return_value = []
        result = dispatch_web_recon_task.run([], "example.com")

    group_mock.assert_not_called()
    web_recon.delay.assert_not_called()
    assert result["web_recon_targets"] == 0
