import logging

from fastapi import FastAPI

from agent_platform.api.routes.evidence import router as evidence_router
from agent_platform.api.routes.policy import router as policy_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = FastAPI(title="Python Agentic Platform API", version="0.1.0")
app.include_router(policy_router)
app.include_router(evidence_router)


@app.get("/api/v1/health", tags=["health"])
def health() -> dict:
    return {"status": "ok"}
