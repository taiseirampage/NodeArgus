import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any

from celery import Task, group

from app.celery_worker import celery_app
from app.config import settings
from app.db import crud
from app.db.database import AsyncSessionLocal
from app.geo.geoip import GeoIPService, open_geo_service
from app.scanner.subfinder_wrapper import SubfinderError, run_subfinder
from app.scanner.validator import validate_domain

from app.tasks.scan import _run_async
from app.tasks.web_recon import run_web_recon_task


logger = logging.getLogger(__name__)

_RESOLVE_CONCURRENCY = 16
_RECON_TOOLS = ("subfinder", "amass")


def _record_fields(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract the hostname and passive source from a Subfinder record."""
    host = record.get("host")
    if not isinstance(host, str) or not host.strip():
        host = record.get("name")
    host = str(host).strip().rstrip(".").lower() if isinstance(host, str) else host
    source = record.get("source")
    if not isinstance(source, str):
        source = None
    return host, source


async def _resolve_host(host: str, semaphore: asyncio.Semaphore) -> list[str]:
    """Resolve a hostname to a list of valid IP addresses, deduplicated."""
    resolved: list[str] = []
    seen: set[str] = set()
    async with semaphore:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, family=socket.AF_UNSPEC
            )
        except (OSError, asyncio.TimeoutError, socket.gaierror):
            return resolved
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        raw = sockaddr[0]
        try:
            ip = str(ipaddress.ip_address(raw))
        except ValueError:
            continue
        if ip not in seen:
            seen.add(ip)
            resolved.append(ip)
    return resolved


async def _resolve_batches(
    hosts: list[str], batch_size: int = 50
) -> dict[str, list[str]]:
    """Resolve hostnames to IPs in bounded batches to limit DNS fan-out."""
    mapping: dict[str, list[str]] = {}
    semaphore = asyncio.Semaphore(_RESOLVE_CONCURRENCY)
    for start in range(0, len(hosts), batch_size):
        chunk = hosts[start : start + batch_size]
        results = await asyncio.gather(
            *(_resolve_host(host, semaphore) for host in chunk)
        )
        mapping.update(zip(chunk, results))
    return mapping


async def _enrich_with_ips(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach resolved IPs to each unique subdomain record."""
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        host, source = _record_fields(record)
        if not host:
            continue
        existing = unique.get(host)
        if existing is None:
            unique[host] = {"name": host, "source": source}
            continue
        if existing.get("source") is None and source is not None:
            existing["source"] = source

    ips_by_host = await _resolve_batches(list(unique.keys()))
    enriched: list[dict[str, Any]] = []
    for host, entry in unique.items():
        entry["ip_addresses"] = ips_by_host.get(host, [])
        enriched.append(entry)
    return enriched


async def _run_recon(target: str) -> dict[str, Any]:
    """Run Subfinder and persist the discovered domains, subdomains, and IPs."""
    domain = validate_domain(target)
    logger.info("Starting passive recon for %s", domain)
    subfinder_records = await run_subfinder(domain)
    if not subfinder_records:
        logger.info("No subdomains found for %s", domain)
        return {"domain": domain, "subdomains": 0, "links": 0}

    enriched = await _enrich_with_ips(subfinder_records)
    geo_service = open_geo_service(settings.GEOIP_DB_PATH)
    try:
        async with AsyncSessionLocal() as db:
            saved_counts = await crud.save_recon_results(
                db, domain, enriched, geo_service
            )
    finally:
        if geo_service is not None:
            geo_service.close()
    counts: dict[str, Any] = {
        "domains": saved_counts["domains"],
        "subdomains": saved_counts["subdomains"],
        "links": saved_counts["links"],
    }
    counts["domain"] = domain
    logger.info(
        "Recon task finished for %s: found %d, saved %d",
        domain,
        len(enriched),
        counts["subdomains"],
    )
    return counts


@celery_app.task(name="run_recon_task", bind=True)
def run_recon_task(self: Task, target: str) -> dict[str, Any]:
    """Enumerate subdomains passively with Subfinder and persist them."""
    try:
        return _run_async(_run_recon(target))
    except (SubfinderError, ValueError) as error:
        logger.exception("Recon task failed for target %s", target)
        raise


@celery_app.task(name="run_subfinder_collect_task", bind=True)
def run_subfinder_collect_task(self: Task, target: str) -> list[str] | dict[str, str]:
    """Collect raw subdomain names from Subfinder without persisting them.

    Instead of raising, a failed collection returns ``{"error": "..."}`` so the
    unified recon coordinator can degrade gracefully and keep partial results.
    """
    try:
        domain = validate_domain(target)
        records = _run_async(run_subfinder(domain))
        names: list[str] = []
        for record in records:
            host, _ = _record_fields(record)
            if host:
                names.append(host)
        return sorted(names)
    except (SubfinderError, ValueError) as error:
        logger.warning("Subfinder collection failed for %s: %s", target, error)
        return {"error": str(error)}


@celery_app.task(name="run_amass_collect_task", bind=True)
def run_amass_collect_task(
    self: Task, target: str, amass_mode: str = "passive"
) -> dict[str, Any]:
    """Collect Amass findings (subdomains, resolved IPs, ASN) without saving.

    A failed run returns ``{"error": "..."}`` so the unified coordinator can
    report the tool as failed while still using the other tool's results.
    """
    from app.scanner.amass_wrapper import AmassError, run_amass

    try:
        domain = validate_domain(target)
        mode: Any = amass_mode if amass_mode in ("passive", "active") else "passive"
        return _run_async(run_amass(domain, mode))
    except (AmassError, ValueError) as error:
        logger.warning("Amass collection failed for %s: %s", target, error)
        return {"error": str(error)}


def _recon_progress(
    task: Task, progress: dict[str, Any], state: str = "PROGRESS"
) -> None:
    """Publish per-tool progress, tolerating in-process ``.run()`` execution.

    When a recon task is invoked synchronously from the full-scan pipeline via
    ``run_unified_recon_task.run(...)``, Celery has not set up a ``Request`` for
    the nested call, so ``self.request.id`` is ``None`` and ``update_state``
    would raise a ``ValueError``. This helper skips the write in that case.
    """
    try:
        request_id = task.request.id
    except Exception:
        request_id = None
    if request_id is None:
        logger.debug("Skipping progress update: task invoked without request id")
        return
    task.update_state(state=state, meta={"progress": progress})


def _merge_recon_subdomains(
    subfinder_names: list[str], amass_names: list[str]
) -> list[dict[str, Any]]:
    """Merge Subfinder and Amass findings into one deduplicated record list.

    The same subdomain is frequently returned by both tools. We keep a single
    record per unique name and record which tools found it in the ``sources``
    list so the downstream persistence step can store composite provenance.

    Args:
        subfinder_names: Subdomains discovered by Subfinder.
        amass_names: Subdomains discovered by Amass.

    Returns:
        A list of dicts with ``name`` and ``sources`` keys.
    """
    records: dict[str, set[str]] = {}
    for name in subfinder_names:
        label = name.strip().rstrip(".").lower()
        if label:
            records.setdefault(label, set()).add("subfinder")
    for name in amass_names:
        label = name.strip().rstrip(".").lower()
        if label:
            records.setdefault(label, set()).add("amass")
    return [
        {"name": name, "sources": sorted(sources)}
        for name, sources in sorted(records.items())
    ]


async def _unified_resolve(
    merged: list[dict[str, Any]], amass_resolved: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Resolve merged subdomains, retaining Amass-provided IPs per name.

    DNS resolution is performed in batches of 50 as with Subfinder-only recon.
    Amass may already have resolved some names during enumeration; those IPs are
    retained alongside a fresh A/AAAA lookup so the two sources are combined.

    Args:
        merged: De-duplicated subdomain records (names + tools).
        amass_resolved: Subdomain → IP mapping produced by Amass.

    Returns:
        The same records with ``ip_addresses`` attached.
    """
    unresolved = [record["name"] for record in merged]
    resolved = await _resolve_batches(unresolved)

    for record in merged:
        name = record["name"]
        ips = set(resolved.get(name, []))
        ips.update(amass_resolved.get(name, []))
        record["ip_addresses"] = sorted(ips)
    return merged


async def _persist_unified_recon(
    domain: str,
    merged: list[dict[str, Any]],
    amass_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve merged subdomains, save domain/ASN, and return recon statistics.

    Even when no subdomains are discovered, the root domain and any Amass ASN
    attribution are still persisted so the graph can render the domain with its
    ASN ownership node instead of returning 404, and Amass-discovered IPs are
    counted even when they are not attached to a subdomain.
    """
    amass_resolved: dict[str, list[str]] = {}
    asn_info: list[dict[str, Any]] = []
    amass_ips: set[str] = set()
    if amass_result and isinstance(amass_result, dict):
        raw_resolved = amass_result.get("resolved") or {}
        amass_resolved = {
            str(name): [str(ip) for ip in ips if isinstance(ip, str)]
            for name, ips in raw_resolved.items()
            if isinstance(ips, list)
        }
        raw_asns = amass_result.get("asn_info") or []
        asn_info = [entry for entry in raw_asns if isinstance(entry, dict)]
        raw_ips = amass_result.get("ip_addresses") or []
        amass_ips = {str(ip) for ip in raw_ips if isinstance(ip, str)}

    enriched = await _unified_resolve(merged, amass_resolved)
    geo_service = open_geo_service(settings.GEOIP_DB_PATH)
    try:
        async with AsyncSessionLocal() as db:
            counts = await crud.save_unified_recon_results(
                db, domain, enriched, asn_info, geo_service
            )
    finally:
        if geo_service is not None:
            geo_service.close()

    resolved_ips = {ip for record in enriched for ip in record.get("ip_addresses", [])}
    resolved_ips.update(amass_ips)
    tools_used = sorted({label for record in merged for label in record["sources"]})
    return {
        "domain": domain,
        "total_subdomains": counts["subdomains"],
        "unique_ips": len(resolved_ips),
        "tools_used": tools_used,
        "asn_info": asn_info,
    }


@celery_app.task(name="run_unified_recon_task", bind=True)
def run_unified_recon_task(
    self: Task,
    target: str,
    recon_tools: list[str] | None = None,
    amass_mode: str = "passive",
) -> dict[str, Any]:
    """Run selected recon tools in parallel, merge, resolve, and persist.

    Subfinder and Amass are dispatched as a Celery ``group`` so both run across
    workers concurrently. Their findings are merged on the caller side: unique
    subdomain names are kept once (with combined ``sources`` provenance),
    resolved in DNS batches of 50, and saved idempotently. ASN attribution from
    Amass is attached to the root ``Domain`` row.

    Celery forbids blocking ``.get()``/``.join()`` inside a task, so the group's
    per-tool results are polled through their own ``AsyncResult`` states; this
    doubles as the per-tool progress exposed by the status endpoint.

    Args:
        target: A validated root FQDN.
        recon_tools: Subset of ``["subfinder", "amass"]`` to run.
        amass_mode: ``passive`` or ``active`` (only used with Amass).

    Returns:
        A dict summarizing total subdomains, unique IPs, used tools, and ASN.
    """
    try:
        domain = validate_domain(target)
    except ValueError as error:
        logger.exception("Unified recon failed for target %s", target)
        raise

    tools = [
        tool
        for tool in (recon_tools if recon_tools is not None else ["subfinder"])
        if tool in _RECON_TOOLS
    ]
    if not tools:
        raise ValueError("recon_tools must include subfinder and/or amass")

    signatures = []
    for tool in tools:
        if tool == "subfinder":
            signatures.append(run_subfinder_collect_task.s(domain))
        else:
            signatures.append(run_amass_collect_task.s(domain, amass_mode))

    _recon_progress(self, {name: "queued" for name in tools})
    workflow = group(signatures)
    group_result = workflow.apply_async()

    deadline = time.time() + 3600
    children = list(group_result.results)
    while time.time() < deadline:
        progress: dict[str, str] = {}
        for tool, child in zip(tools, children):
            try:
                child_state = child.state
            except Exception:
                # A child that somehow reached FAILURE may carry a non-standard
                # result payload; treat it as failed rather than crashing here.
                progress[tool] = "failed"
                continue
            if child_state in ("PENDING", "STARTED", "RETRY"):
                progress[tool] = "running"
            elif child_state == "SUCCESS":
                progress[tool] = "success"
            else:
                progress[tool] = "failed"
        _recon_progress(self, progress)
        try:
            all_done = all(child.ready() for child in children)
        except Exception:
            all_done = False
        if all_done:
            break
        time.sleep(1)

    subfinder_names: list[str] = []
    amass_result: dict[str, Any] | None = None
    tool_errors: dict[str, str] = {}
    for tool, child in zip(tools, children):
        try:
            value = child.result
        except Exception:
            tool_errors[tool] = f"unexpected failure in {tool}"
            continue
        if isinstance(value, dict) and "error" in value:
            tool_errors[tool] = str(value["error"])
            continue
        if tool == "subfinder" and isinstance(value, list):
            if not value or isinstance(value[0], str):
                subfinder_names = value
            else:
                tool_errors[tool] = "subfinder returned malformed results"
        elif tool == "amass" and isinstance(value, dict):
            amass_result = value

    amass_names = list(amass_result.get("subdomains") or []) if amass_result else []
    merged = _merge_recon_subdomains(subfinder_names, amass_names)
    summary = _run_async(_persist_unified_recon(domain, merged, amass_result))
    summary["tools_used"] = tools
    if tool_errors:
        # Amass may legitimately be disabled (ALLOW_ACTIVE_RECON=false) or a tool
        # may have failed: keep partial results instead of failing the pipeline.
        summary["status"] = "partial"
        summary["tool_errors"] = tool_errors
        logger.warning(
            "Unified recon finished with partial results for %s: %s",
            domain,
            tool_errors,
        )
    else:
        summary["status"] = "success"
    try:
        run_web_recon_task.delay(domain)
        logger.info(
            "Dispatched web recon (httpx/katana) for %s after recon phase", domain
        )
        summary["web_recon_dispatched"] = True
    except Exception as error:
        logger.warning(
            "Unable to enqueue web recon after recon for %s: %s", domain, error
        )
        summary["web_recon_dispatched"] = False
    logger.info("Unified recon finished for %s: %s", domain, summary)
    return summary
