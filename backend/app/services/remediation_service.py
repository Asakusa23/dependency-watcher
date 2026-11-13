from __future__ import annotations

from collections import defaultdict

from app.core.versions import compare_versions, is_major_upgrade
from app.models.db_models import Dependency, Scan, Vulnerability


class RemediationService:
    def build(self, scan: Scan) -> dict:
        recommendations: list[dict] = []
        maintenance: list[dict] = []
        version_groups: dict[tuple[str, str], list[Dependency]] = defaultdict(list)
        for dep in scan.dependencies:
            version_groups[(dep.ecosystem, dep.name)].append(dep)

        multi_version_packages = {
            f"{ecosystem}:{name}": sorted({dep.version for dep in deps if dep.version})
            for (ecosystem, name), deps in version_groups.items()
            if len({dep.version for dep in deps if dep.version}) > 1
        }

        for dep in scan.dependencies:
            vulnerabilities = list(dep.vulnerabilities)
            if vulnerabilities:
                candidates = sorted(
                    {version for vuln in vulnerabilities for version in (vuln.fixed_versions or [])},
                    key=lambda value: (compare_versions(value, dep.version) is None, value),
                )
                viable = [version for version in candidates if compare_versions(version, dep.version) == 1]
                recommended = viable[0] if viable else ""
                if not recommended and dep.latest_version and compare_versions(dep.latest_version, dep.version) == 1:
                    recommended = dep.latest_version
                advisories = sorted({vuln.osv_id for vuln in vulnerabilities})
                severity = max(
                    (vuln.severity for vuln in vulnerabilities),
                    key=lambda value: {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}.get(value, 0),
                )
                reasons = [
                    f"Resolves {len(advisories)} known advisor{'y' if len(advisories) == 1 else 'ies'}: {', '.join(advisories[:6])}"
                ]
                if recommended:
                    reasons.append(f"Upgrade from {dep.version or 'unpinned'} to {recommended}")
                else:
                    reasons.append("No fixed version is published by the advisory source; consider mitigations")
                conflicts: list[str] = []
                if recommended and is_major_upgrade(dep.version, recommended):
                    conflicts.append("This is a major version upgrade and may contain breaking changes")
                if not dep.direct:
                    conflicts.append("Transitive dependency: upgrade the parent dependency that pins this version")
                if len(dep.source_files or []) > 1:
                    conflicts.append("Declared in multiple files: " + ", ".join((dep.source_files or [])[:6]))
                package_key = f"{dep.ecosystem}:{dep.name}"
                if package_key in multi_version_packages:
                    conflicts.append(
                        "Multiple versions of this package exist in the scan: "
                        + ", ".join(multi_version_packages[package_key])
                    )
                if dep.version_specifier and recommended and not _specifier_likely_allows(dep.version_specifier, recommended):
                    conflicts.append(
                        f"Declared constraint '{dep.version_specifier}' may not allow {recommended} without updating the manifest"
                    )
                recommendations.append(
                    {
                        "dependency_id": dep.id,
                        "package": dep.name,
                        "ecosystem": dep.ecosystem,
                        "current_version": dep.version,
                        "recommended_version": recommended,
                        "direct": dep.direct,
                        "severity": severity,
                        "priority_level": dep.priority_level,
                        "priority_score": dep.priority_score,
                        "advisories": advisories,
                        "reasons": reasons,
                        "conflicts": conflicts,
                        "fixed_version": recommended,
                        "breaking_risk": (
                            "major"
                            if recommended and is_major_upgrade(dep.version, recommended)
                            else ("unknown" if not recommended else "low")
                        ),
                        "action": "upgrade" if recommended else "manual_review",
                    }
                )
            elif dep.outdated and dep.latest_version:
                maintenance.append(
                    {
                        "dependency_id": dep.id,
                        "package": dep.name,
                        "ecosystem": dep.ecosystem,
                        "current_version": dep.version,
                        "latest_version": dep.latest_version,
                        "direct": dep.direct,
                        "breaking_risk": "major" if is_major_upgrade(dep.version, dep.latest_version) else "low",
                    }
                )

        recommendations.sort(key=lambda item: (-(item["priority_score"] or 0), item["package"]))
        maintenance.sort(key=lambda item: (not item["direct"], item["package"]))
        return {
            "scan_id": scan.id,
            "generated_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "total": len(recommendations),
            "summary": {
                "urgent_upgrades": sum(1 for item in recommendations if item["priority_level"] in {"CRITICAL", "HIGH"}),
                "total_recommendations": len(recommendations),
                "unfixable": sum(1 for item in recommendations if not item["recommended_version"]),
                "maintenance_updates": len(maintenance),
                "multi_version_packages": multi_version_packages,
            },
            "recommendations": recommendations,
            "items": recommendations,
            "maintenance_updates": maintenance,
            "notice": "Dependency Watcher never modifies the scanned project. Apply changes manually and verify tests.",
        }


def _specifier_likely_allows(specifier: str, version: str) -> bool:
    cleaned = specifier.strip()
    if not cleaned or cleaned.startswith(("http", "git", "file:")):
        return True
    try:
        from packaging.specifiers import SpecifierSet

        return SpecifierSet(cleaned).contains(version, prereleases=True)
    except Exception:
        pass
    if cleaned.startswith("^"):
        try:
            base = cleaned[1:].split(".")
            target = version.split(".")
            return base[0] == target[0]
        except (IndexError, ValueError):
            return True
    if cleaned.startswith("~"):
        base = cleaned.lstrip("~=").split(".")
        target = version.split(".")
        return len(base) >= 2 and base[:2] == target[:2]
    return True
