import logging
import time
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db import crud
from app.db.database import get_db
from app.db.schemas import MapAssetResponse, MapAssetsResponse
from app.geo.geoip import open_geo_service


router = APIRouter()
logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 300
_cache: dict[str, Any] = {"at": 0.0, "payload": None}
_geo_attempted: set[str] = set()


@router.get("/map/assets", response_model=MapAssetsResponse)
async def get_map_assets(
    db: AsyncSession = Depends(get_db),
    refresh: bool = False,
) -> MapAssetsResponse:
    """Return all geolocated IPs (with coordinates) for the world map.

    Results are cached for five minutes so panning/zooming the map does not hit
    the database on every tile request. The frontend passes ``?refresh=1`` right
    after a scan finishes so freshly persisted coordinates become visible
    immediately instead of waiting for the cache to expire.

    Before assembling the payload any geolocation still missing on public IPs is
    back-filled, so hosts recorded by older scans (which saved no coordinates)
    also appear once instead of never.

    Args:
        db: The async database session resolved by FastAPI.
        refresh: When True, skip the in-memory cache and re-read the database.

    Returns:
        A ``count`` plus the list of assets with port counts and the highest
        vulnerability severity per IP.
    """
    now = time.monotonic()
    if not refresh:
        cached = _cache["payload"]
        if cached is not None and now - _cache["at"] < CACHE_TTL_SECONDS:
            return cached

    geo_service = open_geo_service(settings.GEOIP_DB_PATH)
    try:
        supplemented = await crud.backfill_ip_geolocation(
            db, geo_service, _geo_attempted
        )
    finally:
        if geo_service is not None:
            geo_service.close()
    if supplemented:
        logger.info("Back-filled geolocation for %d IP(s)", supplemented)

    raw_assets = await crud.get_map_assets(db)
    assets = [MapAssetResponse(**asset) for asset in raw_assets]
    payload = MapAssetsResponse(count=len(assets), assets=assets)
    _cache["at"] = now
    _cache["payload"] = payload
    logger.info("Map assets refreshed: %d geolocated IPs", len(assets))
    return payload
