import ipaddress
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import crud
from app.db.database import get_db
from app.db.schemas import IPDetailsResponse, PortDetailsResponse
from app.scanner.validator import validate_target


router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/ip/{ip}", response_model=IPDetailsResponse)
async def get_ip_details(
    ip: str, db: AsyncSession = Depends(get_db)
) -> IPDetailsResponse:
    """Return stored metadata and ports for one IP address."""
    try:
        normalized_ip = validate_target(ip)
        if "," in normalized_ip or "/" in normalized_ip:
            raise ValueError("a single IP address is required")
        normalized_ip = str(ipaddress.ip_address(normalized_ip))
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ip must be a valid single IP address",
        ) from error

    record = await crud.get_ip_by_address(db, normalized_ip)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="IP not found in database",
        )
    ports = await crud.get_ports_by_ip(db, record.id)
    logger.warning(
        "GET /ip/%s: ip_id=%d ports_found=%d", normalized_ip, record.id, len(ports)
    )
    return IPDetailsResponse(
        ip=str(record.ip_address),
        country=record.country,
        city=record.city,
        os=record.os,
        provider=record.provider,
        scripts_info=record.scripts_info or {},
        traceroute=record.traceroute or [],
        ports=[PortDetailsResponse.model_validate(port) for port in ports],
    )
