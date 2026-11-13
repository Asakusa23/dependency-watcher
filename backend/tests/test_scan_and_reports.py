from __future__ import annotations

import asyncio
import csv
import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from app.core.container import AppContainer
from app.models.db_models import Scan
from app.services.comparison_service import ComparisonService

from .conftest import FakeGithubSource


def test_completed_scan_persists_results(completed_scan: Scan) -> None:
    scan = completed_scan
    assert scan.status == "completed"
    assert scan.total_dependencies == 2
    assert scan.checked_dependencies == 1
    assert scan.unknown_dependencies == 1
    assert scan.vulnerability_count == 1
    assert scan.vulnerable_dependencies == 1
    assert scan.high_count == 1
    assert scan.outdated_count == 1
    assert scan.coverage_percent == 50.0
    assert scan.security_score == 0.0
    assert scan.score_grade == "F"
    assert scan.sources_used and "OSV.dev" in scan.sources_used

    dependencies = {dep.name: dep for dep in scan.dependencies}
    assert dependencies["requests"].inspection_status == "VULNERABLE"
    assert dependencies["requests"].max_severity == "HIGH"
    assert dependencies["requests"].license == "Apache-2.0"
    assert dependencies["urllib3"].inspection_status == "UNKNOWN"
    assert dependencies["urllib3"].risk_flags == ["unpinned"]


def test_reports_and_sbom_are_valid(container: AppContainer, completed_scan: Scan) -> None:
    scan = container.scan_service.get_scan(completed_scan.id, full=True)
    assert scan is not None

    report = json.loads(container.report_service.to_json(scan))
    assert report["scan"]["id"] == scan.id
    assert report["vulnerabilities"][0]["osv_id"] == "GHSA-test-1234-5678"
    assert report["unverified_components"][0]["name"] == "urllib3"
    assert report["errors"]["unverified_count"] == 1

    html = container.report_service.to_html(scan).decode("utf-8")
    assert "<html" in html.lower()
    assert "GHSA-test-1234-5678" in html

    csv_text = container.report_service.to_csv(scan).decode("utf-8")
    assert "GHSA-test-1234-5678" in csv_text
    assert "urllib3" in csv_text

    pdf = container.report_service.to_pdf(scan)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 500

    bom = json.loads(container.sbom_generator.to_json(scan))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert len(bom["components"]) == 2
    assert bom["vulnerabilities"][0]["id"] == "GHSA-test-1234-5678"
    assert bom["metadata"]["component"]["bom-ref"] == f"urn:dependency-watcher:scan:{scan.id}"

    xml = container.sbom_generator.to_xml(scan)
    root = ET.fromstring(xml)
    assert root.tag.endswith("bom")
    assert root.attrib["specVersion"] == "1.5"
    assert "GHSA-test-1234-5678" in xml


def test_csv_report_neutralizes_formula_injection(container: AppContainer, completed_scan: Scan) -> None:
    scan = container.scan_service.get_scan(completed_scan.id, full=True)
    assert scan is not None
    scan.project_name = "=cmd|' /C calc'!A0"
    scan.dependencies[0].name = "-2+3+cmd|' /C calc'!A0"

    rows = list(csv.reader(io.StringIO(container.report_service.to_csv(scan).decode("utf-8-sig"))))
    assert rows[0][0] == "project"
    assert len(rows) >= 2
    for row in rows[1:]:
        assert not row[0].startswith(("=", "+", "-", "@"))
        assert not row[4].startswith(("=", "+", "-", "@"))
    assert rows[1][0] == "'=cmd|' /C calc'!A0"


def test_remediation_provides_fixed_version(container: AppContainer, completed_scan: Scan) -> None:
    scan = container.scan_service.get_scan(completed_scan.id, full=True)
    assert scan is not None
    remediation = container.remediation_service.build(scan)
    assert remediation["total"] >= 1
    assert any(item["fixed_version"] == "2.32.0" for item in remediation["items"])


def test_comparison_reports_direction(
    container: AppContainer,
    settings,
    tmp_path: Path,
) -> None:
    old_project = tmp_path / "old"
    new_project = tmp_path / "new"
    old_project.mkdir()
    new_project.mkdir()
    (old_project / "requirements.txt").write_text("requests==2.25.1\n", encoding="utf-8")
    (new_project / "requirements.txt").write_text("requests==2.30.0\nflask==3.0.0\n", encoding="utf-8")

    old_scan = container.scan_service.create_scan(
        source_type="local",
        project_name="old",
        source_reference=str(old_project),
    )
    new_scan = container.scan_service.create_scan(
        source_type="local",
        project_name="new",
        source_reference=str(new_project),
    )
    asyncio.run(container.scan_service.execute(old_scan.id))
    asyncio.run(container.scan_service.execute(new_scan.id))

    first = container.scan_service.get_scan(old_scan.id, full=True)
    second = container.scan_service.get_scan(new_scan.id, full=True)
    assert first is not None and second is not None
    comparison = ComparisonService().compare(first, second)
    assert comparison["scan_a"]["id"] == old_scan.id
    assert comparison["scan_b"]["id"] == new_scan.id
    assert comparison["delta"]["dependencies"] == 1
    assert comparison["delta"]["vulnerabilities"] == -1
    assert comparison["dependencies"]["added"][0]["name"] == "flask"
    versions = next(item for item in comparison["dependencies"]["version_changed"] if item["name"] == "requests")
    assert versions["old_versions"] == ["2.25.1"]
    assert versions["new_versions"] == ["2.30.0"]
    assert comparison["vulnerabilities"]["resolved"][0]["osv_id"] == "GHSA-test-1234-5678"


def test_github_source_cleanup_removes_managed_directory(
    container: AppContainer,
    settings,
) -> None:
    container.scan_service.github_source = FakeGithubSource()
    scan = container.scan_service.create_scan(
        source_type="github",
        project_name="github-project",
        source_reference="https://github.com/example/project",
    )
    asyncio.run(container.scan_service.execute(scan.id))
    completed = container.scan_service.get_scan(scan.id)
    assert completed is not None
    assert completed.status == "completed"
    assert completed.scan_metadata.get("managed_dir")
    assert not Path(completed.scan_metadata["managed_dir"]).exists()


def test_failed_scan_is_recorded(container: AppContainer, tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    scan = container.scan_service.create_scan(
        source_type="local",
        project_name="missing",
        source_reference=str(missing),
    )
    asyncio.run(container.scan_service.execute(scan.id))
    failed = container.scan_service.get_scan(scan.id)
    assert failed is not None
    assert failed.status == "failed"
    assert failed.phase == "failed"
    assert failed.error_message
