from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.api.middleware import ContentLengthLimitMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware
from app.api.routes_explorer import router as explorer_router
from app.api.routes_reports import router as reports_router
from app.api.routes_scans import router as scans_router
from app.api.routes_system import router as system_router
from app.core.config import AppSettings, build_settings
from app.core.container import AppContainer, build_container
from app.core.logging import configure_logging
from app.core.security import SecurityError, ensure_within


logger = logging.getLogger(__name__)


def create_app(settings: AppSettings | None = None, container: AppContainer | None = None) -> FastAPI:
    configure_logging(os.environ.get("DW_LOG_LEVEL", "INFO"))
    runtime_settings = settings or build_settings()
    if runtime_settings.frontend_dist is None:
        candidate = runtime_settings.data_dir.parent / "frontend" / "dist"
        if (candidate / "index.html").exists():
            runtime_settings.frontend_dist = candidate
    app_container = container or build_container(runtime_settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.container = app_container
        logger.info("Dependency Watcher API %s starting", __version__)
        yield
        app_container.database.dispose()
        logger.info("Dependency Watcher API stopped")

    app = FastAPI(
        title="Dependency Watcher API",
        description=(
            "Local Software Composition Analysis API. Detects dependencies, queries OSV.dev, "
            "assesses remediation priority, generates CycloneDX SBOMs and reports."
        ),
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.state.container = app_container
    app.state.settings = runtime_settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(runtime_settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(ContentLengthLimitMiddleware, limit_bytes=runtime_settings.max_upload_bytes)
    app.add_middleware(RateLimitMiddleware, container=app_container)

    app.include_router(scans_router)
    app.include_router(reports_router)
    app.include_router(explorer_router)
    app.include_router(system_router)

    @app.get("/health", include_in_schema=False)
    def health_alias() -> dict:
        return {"status": "ok", "version": __version__}

    @app.exception_handler(SecurityError)
    async def security_error_handler(request: Request, exc: SecurityError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled API error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    _mount_frontend(app, runtime_settings.frontend_dist)
    return app


def _mount_frontend(app: FastAPI, dist: Path | None) -> None:
    if dist is None or not (dist / "index.html").exists():
        @app.get("/", include_in_schema=False)
        def root() -> dict:
            return {
                "name": "Dependency Watcher API",
                "version": __version__,
                "docs": "/api/docs",
                "message": "Frontend build not found. Run `npm install && npm run build` in frontend/.",
            }
        return
    dist = dist.resolve()
    assets = dist / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/") or full_path in {"api", "health"}:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        candidate = (dist / full_path).resolve()
        try:
            ensure_within(dist, candidate)
        except SecurityError:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")


settings = build_settings()
container = build_container(settings)
app = create_app(settings=settings, container=container)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("DW_HOST", "127.0.0.1"),
        port=int(os.environ.get("DW_PORT", "8000")),
        reload=os.environ.get("DW_RELOAD", "").lower() in {"1", "true", "yes"},
    )


if __name__ == "__main__":
    run()
