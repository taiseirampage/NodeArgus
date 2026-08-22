"""Celery task package for NodeArgus.

The module was historically a single file ``app/tasks.py``. It now lives in a
package so that the passive recon pipeline can be kept separate from the
active scan pipeline. This ``__init__`` re-exports the original task symbols so
existing imports (and ``unittest.mock.patch`` paths) keep working unchanged.
"""

from app.tasks.scan import (
    AsyncSessionLocal,
    GeoIPService,
    _run_async,
    _save_scan_result,
    run_active_scan_task,
    run_masscan,
    run_nmap,
    run_scan_task,
    run_vuln_scan_task,
    run_web_host_vuln_scan_task,
    validate_target,
)

from app.tasks.recon import run_recon_task, run_unified_recon_task
from app.tasks.amass_recon import run_amass_task
from app.tasks.web_recon import run_web_recon_task
from app.tasks.pipeline import dispatch_web_recon_task, run_full_scan_task

__all__ = [
    "AsyncSessionLocal",
    "GeoIPService",
    "_run_async",
    "_save_scan_result",
    "run_active_scan_task",
    "run_masscan",
    "run_nmap",
    "run_scan_task",
    "run_vuln_scan_task",
    "run_web_host_vuln_scan_task",
    "validate_target",
    "run_recon_task",
    "run_unified_recon_task",
    "run_amass_task",
    "run_web_recon_task",
    "dispatch_web_recon_task",
    "run_full_scan_task",
]
