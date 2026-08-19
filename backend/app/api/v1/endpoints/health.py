from fastapi import APIRouter


router = APIRouter()


@router.get("/health", status_code=200)
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "NodeArgus", "version": "0.1.0"}
