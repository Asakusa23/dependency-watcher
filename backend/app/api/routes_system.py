from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.deps import get_container
from app.api.schemas import SettingsUpdateRequest
from app.core.container import AppContainer


router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(container: AppContainer = Depends(get_container)) -> dict:
    database_status = "ok"
    try:
        with container.database.session() as session:
            session.execute(__import__("sqlalchemy").text("SELECT 1"))
    except Exception:
        database_status = "error"
    return {
        "status": "ok" if database_status == "ok" else "degraded",
        "version": __import__("app").__version__,
        "database": database_status,
        "sources": {
            "osv": "enabled" if container.settings.enable_osv else "disabled",
            "registries": "enabled" if container.settings.enable_registry else "disabled",
            "nvd": "enabled" if container.settings.enable_nvd else "disabled",
            "github": "enabled" if container.settings.enable_github else "disabled",
        },
    }


@router.get("/meta")
def meta(container: AppContainer = Depends(get_container)) -> dict:
    return {
        "version": __import__("app").__version__,
        "ecosystems": ["PyPI", "npm", "Maven", "crates.io"],
        "dependency_files": sorted(container.scan_service.scanner.registry.supported_filenames),
        "limits": {
            "max_upload_bytes": container.settings.max_upload_bytes,
            "max_archive_files": container.settings.max_archive_files,
            "max_extracted_bytes": container.settings.max_extracted_bytes,
            "max_project_files": container.settings.max_project_files,
            "max_dependencies": container.settings.max_dependencies,
        },
    }


@router.get("/settings")
def get_settings(container: AppContainer = Depends(get_container)) -> dict:
    return container.settings_service.public()


@router.put("/settings")
def update_settings(
    payload: SettingsUpdateRequest,
    container: AppContainer = Depends(get_container),
) -> dict:
    return container.settings_service.update(payload.model_dump(exclude_unset=True))


@router.delete("/settings/cache")
def clear_cache(container: AppContainer = Depends(get_container)) -> dict:
    container.cache.clear()
    return {"status": "cleared"}


@router.get("/compare")
def compare_scans(
    scan_a: str = Query(min_length=8, max_length=64),
    scan_b: str = Query(min_length=8, max_length=64),
    container: AppContainer = Depends(get_container),
) -> dict:
    first = container.scan_service.get_scan(scan_a, full=True)
    second = container.scan_service.get_scan(scan_b, full=True)
    if first is None or second is None:
        raise HTTPException(status_code=404, detail="One or both scans were not found")
    return container.comparison_service.compare(first, second)
