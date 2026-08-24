import logging
import time
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db.schemas import MapAssetResponse, MapAssetsResponse


router = APIRouter()
logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 300
_cache: dict[str, Any] = {"at": 0.0, "payload": None}


@router.get("/map/assets", response_model=MapAssetsResponse)
async def get_map_assets(db: AsyncSession = Depends(get_db)) -> MapAssetsResponse:
    """Return all geolocated IPs (with coordinates) for the world map.

    Results are cached for five minutes so panning/zooming the map does not hit
    the database on every tile request.

    Args:
        db: The async database session resolved by FastAPI.

    Returns:
        A ``count`` plus the list of assets with port counts and the highest
        vulnerability severity per IP.
    """
    now = time.monotonic()
    cached = _cache["payload"]
    if cached is not None and now - _cache["at"] < CACHE_TTL_SECONDS:
        return cached

    raw_assets = await crud.get_map_assets(db)
    assets = [MapAssetResponse(**asset) for asset in raw_assets]
    payload = MapAssetsResponse(count=len(assets), assets=assets)
    _cache["at"] = now
    _cache["payload"] = payload
    logger.info("Map assets refreshed: %d geolocated IPs", len(assets))
    return payload
