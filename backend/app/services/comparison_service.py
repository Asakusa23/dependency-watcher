from __future__ import annotations

from app.models.db_models import Scan
from app.services.serializers import scan_summary, vulnerability_summary


class ComparisonService:
    def compare(self, scan_a: Scan, scan_b: Scan) -> dict:
        deps_a = {(dep.ecosystem, dep.name, dep.version): dep for dep in scan_a.dependencies}
        deps_b = {(dep.ecosystem, dep.name, dep.version): dep for dep in scan_b.dependencies}
        keys_a, keys_b = set(deps_a), set(deps_b)

        versions_a: dict[tuple[str, str], set[str]] = {}
        versions_b: dict[tuple[str, str], set[str]] = {}
        for ecosystem, name, version in keys_a:
            versions_a.setdefault((ecosystem, name), set()).add(version)
        for ecosystem, name, version in keys_b:
            versions_b.setdefault((ecosystem, name), set()).add(version)

        added = [
            _dep_brief(deps_b[key]) for key in sorted(keys_b - keys_a, key=lambda k: (k[0], k[1], k[2]))
        ]
        removed = [
            _dep_brief(deps_a[key]) for key in sorted(keys_a - keys_b, key=lambda k: (k[0], k[1], k[2]))
        ]
        changed = []
        for package in sorted(set(versions_a) & set(versions_b)):
            old_versions, new_versions = versions_a[package], versions_b[package]
            if old_versions != new_versions:
                changed.append(
                    {
                        "ecosystem": package[0],
                        "name": package[1],
                        "old_versions": sorted(old_versions),
                        "new_versions": sorted(new_versions),
                    }
                )

        vulns_a = {(vuln.osv_id, vuln.dependency.name if vuln.dependency else "", vuln.dependency.version if vuln.dependency else ""): vuln for vuln in scan_a.vulnerabilities}
        vulns_b = {(vuln.osv_id, vuln.dependency.name if vuln.dependency else "", vuln.dependency.version if vuln.dependency else ""): vuln for vuln in scan_b.vulnerabilities}
        new_vulnerabilities = [
            vulnerability_summary(vulns_b[key], include_details=False)
            for key in sorted(set(vulns_b) - set(vulns_a))
        ]
        resolved_vulnerabilities = [
            vulnerability_summary(vulns_a[key], include_details=False)
            for key in sorted(set(vulns_a) - set(vulns_b))
        ]
        return {
            "scan_a": scan_summary(scan_a),
            "scan_b": scan_summary(scan_b),
            "delta": {
                "dependencies": scan_b.total_dependencies - scan_a.total_dependencies,
                "vulnerabilities": scan_b.vulnerability_count - scan_a.vulnerability_count,
                "critical": scan_b.critical_count - scan_a.critical_count,
                "high": scan_b.high_count - scan_a.high_count,
                "security_score": (
                    (scan_b.security_score or 0) - (scan_a.security_score or 0)
                    if scan_b.security_score is not None and scan_a.security_score is not None
                    else None
                ),
            },
            "dependencies": {
                "added": added,
                "removed": removed,
                "version_changed": changed,
                "unchanged_count": len(keys_a & keys_b),
            },
            "vulnerabilities": {
                "new": new_vulnerabilities,
                "resolved": resolved_vulnerabilities,
                "persisted_count": len(set(vulns_a) & set(vulns_b)),
            },
        }


def _dep_brief(dep) -> dict:  # noqa: ANN001
    return {
        "ecosystem": dep.ecosystem,
        "name": dep.name,
        "version": dep.version,
        "direct": dep.direct,
        "inspection_status": dep.inspection_status,
        "max_severity": dep.max_severity,
    }
