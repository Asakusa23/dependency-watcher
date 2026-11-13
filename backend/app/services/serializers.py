from __future__ import annotations

from typing import Any

from app.models.db_models import Dependency, Scan, Vulnerability


def iso(value) -> str | None:  # noqa: ANN001
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def scan_summary(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "project_name": scan.project_name,
        "source_type": scan.source_type,
        "source_reference": scan.source_reference,
        "status": scan.status,
        "phase": scan.phase,
        "progress": scan.progress,
        "created_at": iso(scan.created_at),
        "started_at": iso(scan.started_at),
        "completed_at": iso(scan.completed_at),
        "duration_seconds": scan.duration_seconds,
        "security_score": scan.security_score,
        "score_grade": scan.score_grade,
        "score_breakdown": scan.score_breakdown,
        "coverage_percent": scan.coverage_percent,
        "total_dependencies": scan.total_dependencies,
        "direct_dependencies": scan.direct_dependencies,
        "transitive_dependencies": scan.transitive_dependencies,
        "checked_dependencies": scan.checked_dependencies,
        "unknown_dependencies": scan.unknown_dependencies,
        "vulnerable_dependencies": scan.vulnerable_dependencies,
        "vulnerability_count": scan.vulnerability_count,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "outdated_count": scan.outdated_count,
        "unpinned_count": scan.unpinned_count,
        "deprecated_count": scan.deprecated_count,
        "ecosystems": scan.ecosystems or [],
        "error_message": scan.error_message,
    }


def scan_detail(scan: Scan) -> dict[str, Any]:
    data = scan_summary(scan)
    data.update(
        {
            "dependency_files": scan.dependency_files or [],
            "warnings": scan.warnings or [],
            "errors": scan.errors or [],
            "sources_used": scan.sources_used or [],
            "sbom_serial": scan.sbom_serial,
        }
    )
    return data


def dependency_summary(dep: Dependency) -> dict[str, Any]:
    return {
        "id": dep.id,
        "scan_id": dep.scan_id,
        "name": dep.name,
        "version": dep.version,
        "ecosystem": dep.ecosystem,
        "purl": dep.purl,
        "version_specifier": dep.version_specifier,
        "pinned": dep.pinned,
        "direct": dep.direct,
        "scope": dep.scope,
        "source_files": dep.source_files or [],
        "license": dep.license,
        "latest_version": dep.latest_version,
        "latest_release_date": dep.latest_release_date,
        "outdated": dep.outdated,
        "deprecated": dep.deprecated,
        "deprecation_reason": dep.deprecation_reason,
        "vulnerability_count": dep.vulnerability_count,
        "max_severity": dep.max_severity,
        "priority_level": dep.priority_level,
        "priority_score": dep.priority_score,
        "inspection_status": dep.inspection_status,
        "inspection_message": dep.inspection_message,
        "health_status": dep.health_status,
        "risk_flags": dep.risk_flags or [],
        "risk_reasons": dep.risk_reasons or [],
    }


def vulnerability_summary(vuln: Vulnerability, *, include_details: bool = True) -> dict[str, Any]:
    data = {
        "id": vuln.id,
        "scan_id": vuln.scan_id,
        "dependency_id": vuln.dependency_id,
        "osv_id": vuln.osv_id,
        "aliases": vuln.aliases or [],
        "cve_ids": vuln.cve_ids or [],
        "ghsa_ids": vuln.ghsa_ids or [],
        "summary": vuln.summary,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector,
        "cvss_version": vuln.cvss_version,
        "published": vuln.published,
        "modified": vuln.modified,
        "withdrawn": vuln.withdrawn,
        "fixed_versions": vuln.fixed_versions or [],
        "affected_versions": vuln.affected_versions or [],
        "references": vuln.references or [],
        "source": vuln.source,
        "priority_level": vuln.priority_level,
        "priority_score": vuln.priority_score,
        "priority_reasons": vuln.priority_reasons or [],
        "dependency_name": vuln.dependency.name if vuln.dependency else None,
        "dependency_version": vuln.dependency.version if vuln.dependency else None,
        "dependency_ecosystem": vuln.dependency.ecosystem if vuln.dependency else None,
        "dependency_direct": vuln.dependency.direct if vuln.dependency else None,
    }
    if include_details:
        data["details"] = vuln.details
        data["database_specific"] = vuln.database_specific or {}
    return data
