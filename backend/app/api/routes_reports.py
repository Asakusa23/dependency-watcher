from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.api.deps import get_container
from app.core.container import AppContainer


router = APIRouter(prefix="/api/scans", tags=["reports"])

MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "pdf": "application/pdf",
}


def _completed_scan(container: AppContainer, scan_id: str):
    scan = container.scan_service.get_scan(scan_id, full=True)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in {"pending", "running"}:
        raise HTTPException(status_code=409, detail="Scan is not complete yet")
    return scan


def _filename(scan, extension: str) -> str:  # noqa: ANN001
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", scan.project_name).strip("-") or "project"
    scan_id = scan.id[:8]
    return f"dependency-watcher-{slug}-{scan_id}.{extension}"


@router.get("/{scan_id}/sbom")
def download_sbom(
    scan_id: str,
    format: Literal["json", "xml"] = Query(default="json"),
    container: AppContainer = Depends(get_container),
) -> Response:
    scan = _completed_scan(container, scan_id)
    if format == "json":
        content = container.sbom_generator.to_json(scan).encode("utf-8")
        media = "application/vnd.cyclonedx+json"
        filename = _filename(scan, "cdx.json")
    else:
        content = container.sbom_generator.to_xml(scan).encode("utf-8")
        media = "application/vnd.cyclonedx+xml"
        filename = _filename(scan, "cdx.xml")
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/remediation")
def get_remediation(scan_id: str, container: AppContainer = Depends(get_container)) -> dict:
    scan = _completed_scan(container, scan_id)
    return container.remediation_service.build(scan)


@router.get("/{scan_id}/reports/{format}")
def download_report(
    scan_id: str,
    format: Literal["json", "html", "csv", "pdf"],
    container: AppContainer = Depends(get_container),
) -> Response:
    scan = _completed_scan(container, scan_id)
    if format == "json":
        content = container.report_service.to_json(scan)
    elif format == "html":
        content = container.report_service.to_html(scan)
    elif format == "csv":
        content = container.report_service.to_csv(scan)
    else:
        content = container.report_service.to_pdf(scan)
    filename = _filename(scan, format)
    return Response(
        content=content,
        media_type=MEDIA_TYPES[format],
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
