from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import selectinload

from app.api.deps import client_key, get_container
from app.api.schemas import ScanCreateRequest
from app.core.container import AppContainer
from app.core.security import SecurityError, validate_github_url
from app.models.db_models import Dependency, Scan, Vulnerability
from app.services.serializers import dependency_summary, scan_detail, scan_summary, vulnerability_summary


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])

_SEVERITY_ORDER = case(
    (Vulnerability.severity == "CRITICAL", 0),
    (Vulnerability.severity == "HIGH", 1),
    (Vulnerability.severity == "MEDIUM", 2),
    (Vulnerability.severity == "LOW", 3),
    (Vulnerability.severity == "INFO", 4),
    else_=5,
)


def _enforce_scan_rate(request: Request, container: AppContainer) -> None:
    allowed, retry_after = container.scan_limiter.allow(client_key(request), 1)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit exceeded",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )


def _require_scan(container: AppContainer, scan_id: str, *, full: bool = False) -> Scan:
    scan = container.scan_service.get_scan(scan_id, full=full)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("", status_code=202)
def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    background: BackgroundTasks,
    container: AppContainer = Depends(get_container),
) -> dict:
    _enforce_scan_rate(request, container)
    service = container.scan_service
    metadata: dict = {}
    if payload.source_type == "local":
        if not payload.path:
            raise HTTPException(status_code=422, detail="path is required for local scans")
        try:
            path = service.validate_local_path(payload.path)
        except (SecurityError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        project_name = payload.project_name or path.name or "local-project"
        source_reference = str(path)
        metadata["project_root"] = str(path)
    else:
        if not payload.repository_url:
            raise HTTPException(status_code=422, detail="repository_url is required for GitHub scans")
        if not container.settings.enable_github:
            raise HTTPException(status_code=400, detail="GitHub source is disabled in settings")
        try:
            owner, repo, ref = validate_github_url(payload.repository_url, container.settings.github_hosts)
        except SecurityError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        project_name = payload.project_name or repo
        source_reference = f"https://github.com/{owner}/{repo}" + (f"/tree/{ref}" if ref else "")
        metadata["ref"] = ref or ""
    scan = service.create_scan(
        source_type=payload.source_type,
        project_name=project_name,
        source_reference=source_reference,
        metadata=metadata,
    )
    background.add_task(service.execute, scan.id)
    result = scan_summary(scan)
    result["message"] = "Scan queued"
    return result


@router.post("/upload", status_code=202)
async def upload_scan(
    request: Request,
    background: BackgroundTasks,
    file: UploadFile = File(...),
    project_name: str | None = Form(default=None),
    container: AppContainer = Depends(get_container),
) -> dict:
    _enforce_scan_rate(request, container)
    filename = Path(file.filename or "project.zip").name
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP archives are supported")
    display_name = project_name or Path(filename).stem or "uploaded-project"
    scan = container.scan_service.create_scan(
        source_type="upload",
        project_name=display_name,
        source_reference=filename,
    )
    try:
        await container.scan_service.store_upload(scan, file)
    except SecurityError as exc:
        container.scan_service.delete_scan(scan.id)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to prepare upload for scan %s", scan.id)
        container.scan_service.delete_scan(scan.id)
        raise HTTPException(status_code=500, detail="Failed to process uploaded archive") from exc
    finally:
        await file.close()
    background.add_task(container.scan_service.execute, scan.id)
    result = scan_summary(scan)
    result["message"] = "Upload accepted; scan queued"
    return result


@router.get("")
def list_scans(
    status: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    container: AppContainer = Depends(get_container),
) -> dict:
    with container.database.session() as session:
        filters = []
        if status:
            filters.append(Scan.status == status)
        total = session.scalar(select(func.count()).select_from(Scan).where(*filters)) or 0
        scans = session.scalars(
            select(Scan)
            .where(*filters)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        items = [scan_summary(scan) for scan in scans]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}")
def get_scan(scan_id: str, container: AppContainer = Depends(get_container)) -> dict:
    return scan_detail(_require_scan(container, scan_id))


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, container: AppContainer = Depends(get_container)) -> None:
    if not container.scan_service.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/{scan_id}/dependencies")
def list_dependencies(
    scan_id: str,
    search: str | None = Query(default=None, max_length=255),
    ecosystem: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    inspection_status: str | None = Query(default=None, max_length=24),
    direct: bool | None = None,
    outdated: bool | None = None,
    vulnerable_only: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    container: AppContainer = Depends(get_container),
) -> dict:
    _require_scan(container, scan_id)
    with container.database.session() as session:
        filters = [Dependency.scan_id == scan_id]
        if search:
            pattern = f"%{search.strip()}%"
            filters.append(or_(Dependency.name.ilike(pattern), Dependency.purl.ilike(pattern)))
        if ecosystem:
            filters.append(Dependency.ecosystem == ecosystem)
        if severity:
            filters.append(Dependency.max_severity == severity.upper())
        if inspection_status:
            filters.append(Dependency.inspection_status == inspection_status.upper())
        if direct is not None:
            filters.append(Dependency.direct == direct)
        if outdated is not None:
            filters.append(Dependency.outdated == outdated)
        if vulnerable_only:
            filters.append(Dependency.vulnerability_count > 0)
        total = session.scalar(select(func.count()).select_from(Dependency).where(*filters)) or 0
        deps = session.scalars(
            select(Dependency)
            .where(*filters)
            .order_by(Dependency.priority_score.desc(), Dependency.ecosystem, func.lower(Dependency.name))
            .limit(limit)
            .offset(offset)
        ).all()
        items = [dependency_summary(dep) for dep in deps]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}/vulnerabilities")
def list_vulnerabilities(
    scan_id: str,
    search: str | None = Query(default=None, max_length=255),
    severity: str | None = Query(default=None, max_length=16),
    ecosystem: str | None = Query(default=None, max_length=32),
    include_details: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    container: AppContainer = Depends(get_container),
) -> dict:
    _require_scan(container, scan_id)
    with container.database.session() as session:
        filters = [Vulnerability.scan_id == scan_id]
        if severity:
            filters.append(Vulnerability.severity == severity.upper())
        if ecosystem:
            filters.append(Dependency.ecosystem == ecosystem)
        if search:
            pattern = f"%{search.strip()}%"
            filters.append(
                or_(
                    Vulnerability.osv_id.ilike(pattern),
                    Vulnerability.summary.ilike(pattern),
                    Dependency.name.ilike(pattern),
                )
            )
        base = (
            select(Vulnerability)
            .join(Dependency, Vulnerability.dependency_id == Dependency.id)
            .where(*filters)
        )
        total = session.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .join(Dependency, Vulnerability.dependency_id == Dependency.id)
            .where(*filters)
        ) or 0
        vulnerabilities = session.scalars(
            base.options(selectinload(Vulnerability.dependency))
            .order_by(_SEVERITY_ORDER, Vulnerability.cvss_score.desc(), Vulnerability.osv_id)
            .limit(limit)
            .offset(offset)
        ).all()
        items = [vulnerability_summary(vuln, include_details=include_details) for vuln in vulnerabilities]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}/dependencies/{dependency_id}")
def get_dependency(
    scan_id: str,
    dependency_id: int,
    container: AppContainer = Depends(get_container),
) -> dict:
    with container.database.session() as session:
        dep = session.scalar(
            select(Dependency)
            .where(Dependency.id == dependency_id, Dependency.scan_id == scan_id)
            .options(selectinload(Dependency.vulnerabilities))
        )
        if dep is None:
            raise HTTPException(status_code=404, detail="Dependency not found")
        data = dependency_summary(dep)
        data["vulnerabilities"] = [
            vulnerability_summary(vuln, include_details=False) for vuln in dep.vulnerabilities
        ]
    return data
