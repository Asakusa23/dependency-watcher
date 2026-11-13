from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.deps import get_container
from app.core.container import AppContainer
from app.models.db_models import Dependency, Vulnerability
from app.services.serializers import dependency_summary, vulnerability_summary


router = APIRouter(prefix="/api", tags=["explorer"])


@router.get("/dependencies/{dependency_id}")
def get_dependency(dependency_id: int, container: AppContainer = Depends(get_container)) -> dict:
    with container.database.session() as session:
        dep = session.scalar(
            select(Dependency)
            .where(Dependency.id == dependency_id)
            .options(selectinload(Dependency.vulnerabilities))
        )
        if dep is None:
            raise HTTPException(status_code=404, detail="Dependency not found")
        data = dependency_summary(dep)
        data["vulnerabilities"] = [
            vulnerability_summary(vuln, include_details=False) for vuln in dep.vulnerabilities
        ]
    return data


@router.get("/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: int, container: AppContainer = Depends(get_container)) -> dict:
    with container.database.session() as session:
        vuln = session.scalar(
            select(Vulnerability)
            .where(Vulnerability.id == vulnerability_id)
            .options(selectinload(Vulnerability.dependency))
        )
        if vuln is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        data = vulnerability_summary(vuln)
    return data
