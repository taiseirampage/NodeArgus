import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.graph import router as graph_router
from app.api.v1.endpoints.ip import router as ip_router
from app.api.v1.endpoints.scan import router as scan_router
from app.api.v1.endpoints.vuln import router as vuln_router


app = FastAPI(title="NodeArgus", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(graph_router)
app.include_router(ip_router)
app.include_router(scan_router)
app.include_router(vuln_router, prefix="/vuln", tags=["vulnerabilities"])


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
