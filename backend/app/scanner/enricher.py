import ipaddress
import logging

from app.geo.geoip import GeoIPService
from app.geo.models import GeoLocation
from app.db import crud
from app.db.models import IP
from sqlalchemy.ext.asyncio import AsyncSession

from .models import MasscanResult, NmapResult


logger = logging.getLogger(__name__)
ScanResult = MasscanResult | NmapResult


def _target_ip(target: str) -> str | None:
    first_target = target.split(",", maxsplit=1)[0].strip()
    try:
        return str(ipaddress.ip_address(first_target))
    except ValueError:
        try:
            return str(ipaddress.ip_network(first_target, strict=False).network_address)
        except ValueError:
            return None


def enrich_scan_result(result: ScanResult, geo_service: GeoIPService) -> ScanResult:
    """Attach local GeoIP data to a Masscan or Nmap result.

    Args:
        result: Scan result whose target should be geolocated.
        geo_service: Initialized local GeoIP service.

    Returns:
        The same scan result object with its ``geo`` field populated when found.
    """
    target_ip = _target_ip(result.target)
    if target_ip is None:
        logger.warning(
            "Cannot derive an IP address from scan target: %s", result.target
        )
        return result
    result.geo = geo_service.lookup(target_ip)
    return result


async def save_to_db(result: NmapResult, geo: GeoLocation, db: AsyncSession) -> IP:
    """Persist an Nmap result and its GeoIP data through the CRUD layer.

    Args:
        result: Nmap services and OS detection result.
        geo: Geolocation for the scanned IP.
        db: Active asynchronous SQLAlchemy session.

    Returns:
        The created or updated IP ORM object.
    """
    return await crud.save_scan_result(db=db, result=result, geo=geo)
