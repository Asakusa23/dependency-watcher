from __future__ import annotations

import io

from fastapi.testclient import TestClient

from .conftest import make_zip


def test_system_endpoints(client: TestClient) -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["database"] == "ok"
    assert health.json()["sources"]["osv"] == "enabled"

    meta = client.get("/api/meta")
    assert meta.status_code == 200
    assert "npm" in meta.json()["ecosystems"]
    assert "requirements.txt" in meta.json()["dependency_files"]

    settings = client.get("/api/settings")
    assert settings.status_code == 200
    assert "enable_osv" in settings.json()


def test_settings_update_and_cache_clear(client: TestClient) -> None:
    response = client.put(
        "/api/settings",
        json={
            "enable_nvd": True,
            "http_timeout_seconds": 15,
            "nvd_api_key": "secret-value",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["enable_nvd"] is True
    assert body["http_timeout_seconds"] == 15
    assert body["nvd_api_key_configured"] is True
    assert "secret-value" not in response.text

    cleared = client.delete("/api/settings/cache")
    assert cleared.status_code == 200
    assert cleared.json()["status"] == "cleared"


def test_local_scan_lifecycle_and_reports(client: TestClient, sample_project) -> None:
    created = client.post(
        "/api/scans",
        json={
            "source_type": "local",
            "path": str(sample_project),
            "project_name": "api-sample",
        },
    )
    assert created.status_code == 202
    scan_id = created.json()["id"]

    detail = client.get(f"/api/scans/{scan_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "completed"
    assert body["total_dependencies"] == 2
    assert body["vulnerability_count"] == 1

    scans = client.get("/api/scans")
    assert scans.status_code == 200
    assert scans.json()["total"] == 1

    dependencies = client.get(f"/api/scans/{scan_id}/dependencies")
    assert dependencies.status_code == 200
    assert dependencies.json()["total"] == 2

    filtered = client.get(
        f"/api/scans/{scan_id}/dependencies",
        params={"vulnerable_only": "true"},
    )
    assert filtered.json()["total"] == 1
    dependency_id = filtered.json()["items"][0]["id"]

    dependency = client.get(f"/api/scans/{scan_id}/dependencies/{dependency_id}")
    assert dependency.status_code == 200
    assert dependency.json()["name"] == "requests"

    vulnerabilities = client.get(f"/api/scans/{scan_id}/vulnerabilities")
    assert vulnerabilities.status_code == 200
    assert vulnerabilities.json()["total"] == 1
    assert vulnerabilities.json()["items"][0]["osv_id"] == "GHSA-test-1234-5678"

    remediation = client.get(f"/api/scans/{scan_id}/remediation")
    assert remediation.status_code == 200
    assert remediation.json()["total"] >= 1

    report = client.get(f"/api/scans/{scan_id}/reports/json")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/json")
    assert report.json()["scan"]["id"] == scan_id

    html = client.get(f"/api/scans/{scan_id}/reports/html")
    assert html.status_code == 200
    assert b"GHSA-test-1234-5678" in html.content

    csv_report = client.get(f"/api/scans/{scan_id}/reports/csv")
    assert csv_report.status_code == 200
    assert b"requests" in csv_report.content

    pdf = client.get(f"/api/scans/{scan_id}/reports/pdf")
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")

    sbom_json = client.get(f"/api/scans/{scan_id}/sbom", params={"format": "json"})
    assert sbom_json.status_code == 200
    assert sbom_json.json()["bomFormat"] == "CycloneDX"

    sbom_xml = client.get(f"/api/scans/{scan_id}/sbom", params={"format": "xml"})
    assert sbom_xml.status_code == 200
    assert b"CycloneDX" in sbom_xml.content

    deleted = client.delete(f"/api/scans/{scan_id}")
    assert deleted.status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_upload_scan_and_zip_traversal_rejection(client: TestClient) -> None:
    payload = make_zip({"project/requirements.txt": "requests==2.25.1\n"})
    uploaded = client.post(
        "/api/scans/upload",
        files={"file": ("project.zip", payload, "application/zip")},
        data={"project_name": "uploaded"},
    )
    assert uploaded.status_code == 202
    scan_id = uploaded.json()["id"]
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "completed"

    bad = make_zip({"../escape.txt": "secret"})
    rejected = client.post(
        "/api/scans/upload",
        files={"file": ("bad.zip", io.BytesIO(bad), "application/zip")},
    )
    assert rejected.status_code == 400
    assert "traversal" in rejected.json()["detail"].lower()


def test_compare_endpoint(client: TestClient, sample_project, tmp_path) -> None:
    newer = tmp_path / "newer"
    newer.mkdir()
    (newer / "requirements.txt").write_text("requests==2.30.0\nflask==3.0.0\n", encoding="utf-8")

    first = client.post(
        "/api/scans",
        json={"source_type": "local", "path": str(sample_project), "project_name": "old"},
    ).json()["id"]
    second = client.post(
        "/api/scans",
        json={"source_type": "local", "path": str(newer), "project_name": "new"},
    ).json()["id"]

    comparison = client.get("/api/compare", params={"scan_a": first, "scan_b": second})
    assert comparison.status_code == 200
    body = comparison.json()
    assert body["scan_a"]["id"] == first
    assert body["scan_b"]["id"] == second
    assert body["delta"]["vulnerabilities"] == -1
    assert body["dependencies"]["added"][0]["name"] == "flask"


def test_invalid_requests(client: TestClient, tmp_path) -> None:
    missing_path = client.post("/api/scans", json={"source_type": "local"})
    assert missing_path.status_code == 422

    bad_path = client.post(
        "/api/scans",
        json={"source_type": "local", "path": str(tmp_path / "missing")},
    )
    assert bad_path.status_code == 400

    bad_github = client.post(
        "/api/scans",
        json={"source_type": "github", "repository_url": "http://github.com/example/project"},
    )
    assert bad_github.status_code == 400

    assert client.get("/api/scans/does-not-exist").status_code == 404
    assert client.get("/api/compare", params={"scan_a": "a" * 8, "scan_b": "b" * 8}).status_code == 404
    assert client.get("/api/scans/does-not-exist/reports/json").status_code == 404
