from __future__ import annotations

import asyncio
import logging
import shutil
import time
import uuid
from pathlib import Path

from fastapi import UploadFile
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import AppSettings
from app.core.security import SecurityError, new_work_dir, safe_extract_zip
from app.database.base import utcnow
from app.database.session import Database
from app.models.db_models import Dependency, Scan, Vulnerability
from app.risk_engine.engine import RiskEngine, max_severity, security_score
from app.scanners.github import GitHubSource
from app.scanners.scanner import ProjectScanner, ScanResult
from app.services.health_service import DependencyHealthEngine
from app.vulnerability_engine.cache import CacheStore
from app.vulnerability_engine.engine import (
    STATUS_CHECKED,
    STATUS_VULNERABLE,
    VulnerabilityEngine,
    VulnerabilityScanOutcome,
)


logger = logging.getLogger(__name__)


class ScanService:
    def __init__(
        self,
        settings: AppSettings,
        database: Database,
        *,
        cache: CacheStore,
        scanner: ProjectScanner | None = None,
        vulnerability_engine: VulnerabilityEngine | None = None,
        health_engine: DependencyHealthEngine | None = None,
        risk_engine: RiskEngine | None = None,
        github_source: GitHubSource | None = None,
    ) -> None:
        self.settings = settings
        self.database = database
        self.cache = cache
        self.scanner = scanner or ProjectScanner(settings)
        self.vulnerability_engine = vulnerability_engine or VulnerabilityEngine(settings, cache)
        self.health_engine = health_engine
        self.risk_engine = risk_engine or RiskEngine()
        self.github_source = github_source or GitHubSource(settings)

    # ------------------------------------------------------------------ creation
    def create_scan(
        self,
        *,
        source_type: str,
        project_name: str,
        source_reference: str,
        metadata: dict | None = None,
    ) -> Scan:
        scan = Scan(
            id=uuid.uuid4().hex,
            project_name=_sanitize_name(project_name) or "Unknown project",
            source_type=source_type,
            source_reference=source_reference[:2000],
            status="pending",
            phase="queued",
            progress=0,
            created_at=utcnow(),
            scan_metadata=metadata or {},
        )
        with self.database.session() as session:
            session.add(scan)
            session.commit()
            session.refresh(scan)
        return scan

    def get_scan(self, scan_id: str, *, full: bool = False) -> Scan | None:
        with self.database.session() as session:
            query = select(Scan).where(Scan.id == scan_id)
            if full:
                query = query.options(
                    selectinload(Scan.dependencies).selectinload(Dependency.vulnerabilities),
                    selectinload(Scan.vulnerabilities).selectinload(Vulnerability.dependency),
                )
            scan = session.scalar(query)
            if scan is not None:
                session.expunge_all()
            return scan

    def delete_scan(self, scan_id: str) -> bool:
        scan = self.get_scan(scan_id)
        if scan is None:
            return False
        self._cleanup_managed(scan.scan_metadata or {})
        with self.database.session() as session:
            obj = session.get(Scan, scan_id)
            if obj is None:
                return False
            session.delete(obj)
            session.commit()
        return True

    def validate_local_path(self, raw_path: str) -> Path:
        if not self.settings.allow_local_paths:
            raise SecurityError("Local path scanning is disabled in settings")
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            raise SecurityError("Local path must be absolute")
        resolved = path.resolve(strict=True)
        if not resolved.is_dir():
            raise SecurityError("Local path is not a directory")
        return resolved

    async def store_upload(self, scan: Scan, upload: UploadFile) -> Path:
        work = new_work_dir(self.settings.work_dir, scan.id)
        archive = work / "upload.zip"
        written = 0
        try:
            with open(archive, "wb") as output:
                while True:
                    chunk = await upload.read(1024 * 256)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > self.settings.max_upload_bytes:
                        raise SecurityError(
                            f"Upload exceeds the {self.settings.max_upload_bytes // (1024 * 1024)} MiB limit"
                        )
                    output.write(chunk)
            if written == 0:
                raise SecurityError("Uploaded archive is empty")
            extracted = await asyncio.to_thread(
                safe_extract_zip,
                archive,
                work / "project",
                max_files=self.settings.max_archive_files,
                max_total_bytes=self.settings.max_extracted_bytes,
                max_file_bytes=self.settings.max_extracted_bytes,
            )
            self._set_metadata(
                scan.id,
                {
                    "project_root": str(extracted.root),
                    "managed_dir": str(work),
                    "files_extracted": extracted.files_extracted,
                    "bytes_extracted": extracted.bytes_extracted,
                },
            )
            return extracted.root
        except Exception:
            shutil.rmtree(work, ignore_errors=True)
            raise
        finally:
            archive.unlink(missing_ok=True)

    def _set_metadata(self, scan_id: str, extra: dict) -> None:
        with self.database.session() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            metadata = dict(scan.scan_metadata or {})
            metadata.update(extra)
            scan.scan_metadata = metadata
            session.commit()

    # ------------------------------------------------------------------ execution
    async def execute(self, scan_id: str) -> None:
        started = time.perf_counter()
        managed: dict = {}
        try:
            scan = self.get_scan(scan_id)
            if scan is None:
                return
            managed = dict(scan.scan_metadata or {})
            self._update_scan(
                scan_id,
                status="running",
                phase="acquiring_source",
                progress=5,
                started_at=utcnow(),
                error_message=None,
            )
            root = await self._acquire_source(scan)
            latest = self.get_scan(scan_id)
            managed = dict(latest.scan_metadata or {}) if latest is not None else managed
            self._update_scan(scan_id, phase="discovering_dependencies", progress=15)
            result: ScanResult = await asyncio.to_thread(self.scanner.scan, root)
            self._update_scan(
                scan_id,
                phase="inspecting_dependencies",
                progress=35,
                total_dependencies=len(result.dependencies),
                direct_dependencies=sum(1 for dep in result.dependencies if dep.direct),
                transitive_dependencies=sum(1 for dep in result.dependencies if not dep.direct),
                unpinned_count=sum(1 for dep in result.dependencies if not dep.pinned),
                dependency_files=result.dependency_files,
                ecosystems=result.ecosystems,
                warnings=result.warnings,
                errors=result.errors,
                scan_metadata={**managed, "project_type": result.project_type, "project_files_scanned": result.project_files_scanned},
            )
            dependency_rows = self._persist_dependencies(scan_id, result)
            self._update_scan(scan_id, phase="querying_vulnerability_sources", progress=50)
            queries = [
                (str(index), dep.name, dep.version, dep.ecosystem)
                for index, dep in enumerate(dependency_rows)
            ]
            vuln_task = asyncio.create_task(self.vulnerability_engine.scan(queries))
            health_task = asyncio.create_task(self.health_engine.check(queries)) if self.health_engine else None
            outcome: VulnerabilityScanOutcome = await vuln_task
            health = await health_task if health_task is not None else {}
            self._update_scan(scan_id, phase="assessing_risk", progress=80)
            summary = self._apply_results(scan_id, dependency_rows, result, outcome, health)
            score = security_score(**summary["score_inputs"])
            duration = round(time.perf_counter() - started, 3)
            warnings = list(result.warnings)
            warnings.extend(outcome.warnings)
            warnings.extend(summary["warnings"])
            sources = list(outcome.sources_used)
            if self.settings.enable_registry:
                sources.append("Package registries (latest versions/licenses)")
            self._update_scan(
                scan_id,
                status="completed",
                phase="completed",
                progress=100,
                completed_at=utcnow(),
                duration_seconds=duration,
                security_score=score.score,
                score_grade=score.grade,
                score_breakdown=score.breakdown,
                coverage_percent=score.breakdown.get("coverage_percent", 0.0),
                vulnerability_count=summary["vulnerability_count"],
                vulnerable_dependencies=summary["vulnerable_dependencies"],
                checked_dependencies=summary["checked_dependencies"],
                unknown_dependencies=summary["unknown_dependencies"],
                critical_count=summary["critical"],
                high_count=summary["high"],
                medium_count=summary["medium"],
                low_count=summary["low"],
                info_count=summary["info"],
                outdated_count=summary["outdated"],
                deprecated_count=summary["deprecated"],
                sbom_serial=uuid.uuid4().hex,
                warnings=warnings[:300],
                sources_used=sorted(set(sources)),
            )
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            self._update_scan(
                scan_id,
                status="failed",
                phase="failed",
                error_message=_safe_error(exc),
                completed_at=utcnow(),
                duration_seconds=round(time.perf_counter() - started, 3),
            )
        finally:
            latest = self.get_scan(scan_id)
            if latest is not None:
                self._cleanup_managed(latest.scan_metadata or {})
            elif managed:
                self._cleanup_managed(managed)

    async def _acquire_source(self, scan: Scan) -> Path:
        metadata = dict(scan.scan_metadata or {})
        if scan.source_type == "local":
            return self.validate_local_path(scan.source_reference)
        if scan.source_type == "upload":
            root_value = metadata.get("project_root")
            if not root_value:
                raise SecurityError("Uploaded project was not prepared")
            root = Path(root_value).resolve()
            if not root.is_dir():
                raise SecurityError("Extracted upload directory is missing")
            return root
        if scan.source_type == "github":
            work = new_work_dir(self.settings.work_dir, scan.id)
            self._set_metadata(scan.id, {"managed_dir": str(work)})
            extracted = await self.github_source.download(scan.source_reference, work)
            self._set_metadata(
                scan.id,
                {
                    "project_root": str(extracted.root),
                    "files_extracted": extracted.files_extracted,
                    "bytes_extracted": extracted.bytes_extracted,
                },
            )
            return extracted.root
        raise SecurityError("Unsupported scan source type")

    def _persist_dependencies(self, scan_id: str, result: ScanResult) -> list[Dependency]:
        rows: list[Dependency] = []
        with self.database.session() as session:
            for parsed in result.dependencies:
                dep = Dependency(
                    scan_id=scan_id,
                    ecosystem=parsed.ecosystem,
                    name=parsed.name,
                    version=parsed.version,
                    version_specifier=parsed.specifier,
                    purl=parsed.purl,
                    pinned=parsed.pinned,
                    direct=parsed.direct,
                    scope=parsed.scope,
                    source_files=parsed.source_files or ([parsed.source_file] if parsed.source_file else []),
                    license=parsed.license,
                    inspection_status="PENDING",
                )
                session.add(dep)
                rows.append(dep)
            session.commit()
            for row in rows:
                session.refresh(row)
                session.expunge(row)
        return rows

    def _apply_results(
        self,
        scan_id: str,
        dependencies: list[Dependency],
        result: ScanResult,
        outcome: VulnerabilityScanOutcome,
        health: dict,
    ) -> dict:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        vulnerable_dependencies = 0
        checked = 0
        outdated = 0
        deprecated = 0
        warnings: list[str] = []
        vulnerability_count = 0

        with self.database.session() as session:
            for index, dep in enumerate(dependencies):
                db_dep = session.get(Dependency, dep.id)
                if db_dep is None:
                    continue
                key = str(index)
                inspection = outcome.inspections.get(key)
                health_info = health.get(key)
                active_vulns = []
                assessments = []
                if inspection is not None:
                    for vuln in inspection.vulnerabilities:
                        if vuln.withdrawn:
                            continue
                        active_vulns.append(vuln)
                if inspection is not None:
                    db_dep.inspection_status = inspection.status
                    db_dep.inspection_message = inspection.message
                    if inspection.status in {STATUS_CHECKED, STATUS_VULNERABLE}:
                        checked += 1
                else:
                    db_dep.inspection_status = "UNKNOWN"
                    db_dep.inspection_message = "Dependency was not inspected"
                if health_info is not None:
                    db_dep.latest_version = health_info.latest_version
                    db_dep.latest_release_date = health_info.release_date
                    db_dep.outdated = health_info.outdated
                    db_dep.deprecated = health_info.deprecated
                    db_dep.deprecation_reason = health_info.deprecation_reason
                    db_dep.health_status = health_info.health_status
                    if health_info.license:
                        db_dep.license = health_info.license
                    if health_info.error:
                        db_dep.risk_flags = list(db_dep.risk_flags or []) + ["registry_unavailable"]
                        warnings.append(f"Registry metadata unavailable for {db_dep.name}: {health_info.error}")
                if not db_dep.license:
                    db_dep.health_status = db_dep.health_status or "UNKNOWN"
                if db_dep.outdated:
                    outdated += 1
                if db_dep.deprecated:
                    deprecated += 1
                for vuln in active_vulns:
                    assessment = self.risk_engine.assess_vulnerability(vuln, direct=db_dep.direct)
                    assessments.append((vuln, assessment))
                    db_vuln = Vulnerability(
                        scan_id=scan_id,
                        dependency_id=db_dep.id,
                        osv_id=vuln.osv_id,
                        aliases=vuln.aliases,
                        cve_ids=vuln.cve_ids,
                        ghsa_ids=vuln.ghsa_ids,
                        summary=vuln.summary,
                        details=vuln.details,
                        severity=vuln.severity,
                        cvss_score=vuln.cvss_score,
                        cvss_vector=vuln.cvss_vector,
                        cvss_version=vuln.cvss_version,
                        published=vuln.published,
                        modified=vuln.modified,
                        withdrawn=vuln.withdrawn,
                        fixed_versions=vuln.fixed_versions,
                        affected_versions=vuln.affected_versions,
                        references=vuln.references,
                        source=vuln.source,
                        priority_level=assessment.level,
                        priority_score=assessment.score,
                        priority_reasons=assessment.reasons,
                        database_specific=vuln.database_specific,
                    )
                    session.add(db_vuln)
                    vulnerability_count += 1
                    if vuln.severity in severity_counts:
                        severity_counts[vuln.severity] += 1
                aggregate = self.risk_engine.assess_dependency(
                    vulnerabilities=assessments,
                    deprecated=db_dep.deprecated,
                    outdated=db_dep.outdated,
                    pinned=db_dep.pinned,
                    direct=db_dep.direct,
                )
                db_dep.vulnerability_count = len(active_vulns)
                db_dep.max_severity = max_severity([vuln.severity for vuln in active_vulns])
                db_dep.priority_level = aggregate.level
                db_dep.priority_score = aggregate.score
                db_dep.risk_reasons = aggregate.reasons
                db_dep.checked_at = utcnow()
                if active_vulns:
                    vulnerable_dependencies += 1
                if not db_dep.pinned:
                    db_dep.risk_flags = list(db_dep.risk_flags or []) + ["unpinned"]
                if db_dep.deprecated:
                    db_dep.risk_flags = list(db_dep.risk_flags or []) + ["deprecated"]
            session.commit()

        total = len(dependencies)
        unknown = max(0, total - checked)
        return {
            "vulnerability_count": vulnerability_count,
            "vulnerable_dependencies": vulnerable_dependencies,
            "checked_dependencies": checked,
            "unknown_dependencies": unknown,
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "info": severity_counts["INFO"],
            "outdated": outdated,
            "deprecated": deprecated,
            "warnings": warnings,
            "score_inputs": {
                "total": total,
                "checked": checked,
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
                "info": severity_counts["INFO"],
                "outdated": outdated,
                "deprecated": deprecated,
            },
        }

    def _update_scan(self, scan_id: str, **fields) -> None:  # noqa: ANN003
        with self.database.session() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                return
            for key, value in fields.items():
                if key == "scan_metadata":
                    scan.scan_metadata = value
                else:
                    setattr(scan, key, value)
            session.commit()

    def _cleanup_managed(self, metadata: dict) -> None:
        raw = metadata.get("managed_dir")
        if not raw:
            return
        path = Path(raw).resolve()
        work_root = self.settings.work_dir.resolve()
        if work_root in path.parents or path == work_root:
            shutil.rmtree(path, ignore_errors=True)


def _sanitize_name(value: str) -> str:
    return "".join(ch for ch in value.strip() if ch.isprintable())[:255]


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, SecurityError):
        return str(exc)[:1000]
    return f"{type(exc).__name__}: {exc}"[:1000]
