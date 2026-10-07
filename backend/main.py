"""FastAPI application factory; runtime authentication is installed by bootstrap."""

from pathlib import Path

from fastapi import FastAPI

from shared.schemas import HealthResponse


def create_app(instance_token: str, instance_id: str, profile: Path) -> FastAPI:
    """Build an isolated app; serving it requires the authenticated TLS bootstrap."""
    if not instance_token or not instance_id:
        raise ValueError("Instance token and identity are required")
    app = FastAPI(title="Toolkit", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.profile = profile
    app.state.instance_id = instance_id
    app.state.instance_token = instance_token

    @app.get("/api/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(instance_id=instance_id)

    return app
