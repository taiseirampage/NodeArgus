from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.graph.compute import compute_graph_for_target
from app.graph.models import GraphResponse


router = APIRouter()


@router.get("/graph/{target}", response_model=GraphResponse)
async def get_graph(target: str, db: AsyncSession = Depends(get_db)) -> GraphResponse:
    """Return graph nodes and links for an IP, CIDR, or domain target."""
    try:
        return await compute_graph_for_target(db, target)
    except HTTPException:
        raise
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
