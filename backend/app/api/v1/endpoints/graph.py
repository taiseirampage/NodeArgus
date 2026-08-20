from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.graph.compute import compute_graph
from app.graph.models import GraphResponse
from app.scanner.validator import validate_target


router = APIRouter()


@router.get("/graph/{ip}", response_model=GraphResponse)
async def get_graph(ip: str, db: AsyncSession = Depends(get_db)) -> GraphResponse:
    """Return graph nodes and links for one validated IP address."""
    try:
        validated_target = validate_target(ip)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ip must be a valid IP address",
        ) from error
    return await compute_graph(db, validated_target)
