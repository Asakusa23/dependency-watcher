from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path

import pytest

from app.core.config import AppSettings
from app.core.container import AppContainer, build_container
from app.core.security import ExtractedProject
from app.models.db_models import Scan
from app.services.health_service import HealthResult
from app.vulnerability_engine.engine import DependencyInspection, VulnerabilityEngine, VulnerabilityScanOutcome
from app.vulnerability_engine.osv import OsvVulnerability


def make_settings(tmp_path: Path, **overrides) -> AppSettings:
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    values = dict(
        data_dir=data_dir,
        database_url=f"sqlite:///{(data_dir / 'test.db').as_posix()}",
        cache_path=data_dir / "cache.db",
        settings_path=data_dir / "settings.json",
        work_dir=data_dir / "work",
        enable_registry=False,
        enable_osv=True,
        enable_nvd=False,
        http_timeout_seconds=5.0,
        rate_limit_per_minute=10_000,
        scan_rate_limit_per_hour=10_000,
    )
    values.update(overrides)
    settings = AppSettings(**values)
    settings.work_dir.mkdir(parents=True, exist_ok=True)
    return settings


def vulnerability() -> OsvVulnerability:
    return OsvVulnerability(
        osv_id="GHSA-test-1234-5678",
        aliases=["CVE-2026-9999"],
        cve_ids=["CVE-2026-9999"],
        ghsa_ids=["GHSA-test-1234-5678"],
        summary="Test request smuggling vulnerability",
        details="A vulnerability used only by the test suite.",
        severity="HIGH",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_version="3.1",
        published="2026-01-01T00:00:00Z",
        fixed_versions=["2.32.0"],
        affected_versions=["<2.32.0"],
        references=[{"type": "WEB", "url": "https://osv.dev/GHSA-test-1234-5678"}],
    )


class FakeOsvClient:
    async def query_batch(self, queries):
        results: dict[str, list[str]] = {}
        for query in queries:
            if query.name == "requests" and query.version == "2.25.1":
                results[query.key] = ["GHSA-test-1234-5678"]
            else:
                results[query.key] = []
        return results

    async def fetch_vulnerabilities(self, ids):
        return {osv_id: vulnerability() for osv_id in ids}


class FakeNvdClient:
    async def enrich(self, vulnerabilities):
        return None


class FakeHealthEngine:
    async def check(self, dependencies):
        results: dict[str, HealthResult] = {}
        for key, name, version, ecosystem in dependencies:
            if name == "requests":
                results[key] = HealthResult(
                    latest_version="2.32.5",
                    license="Apache-2.0",
                    outdated=True,
                    health_status="OUTDATED",
                )
            else:
                results[key] = HealthResult(
                    latest_version=version,
                    license="MIT",
                    outdated=False,
                    health_status="HEALTHY",
                )
        return results


class FakeGithubSource:
    async def download(self, repository_url: str, destination: Path) -> ExtractedProject:
        root = destination / "project"
        root.mkdir(parents=True, exist_ok=True)
        payload = "requests==2.25.1\n"
        (root / "requirements.txt").write_text(payload, encoding="utf-8")
        return ExtractedProject(root=root, files_extracted=1, bytes_extracted=len(payload))


@pytest.fixture()
def settings(tmp_path: Path) -> AppSettings:
    return make_settings(tmp_path)


@pytest.fixture()
def container(settings: AppSettings) -> AppContainer:
    app_container = build_container(settings)
    app_container.scan_service.vulnerability_engine = VulnerabilityEngine(
        settings,
        app_container.cache,
        osv=FakeOsvClient(),
        nvd=FakeNvdClient(),
    )
    app_container.scan_service.health_engine = FakeHealthEngine()
    yield app_container
    app_container.database.dispose()


@pytest.fixture()
def sample_project(tmp_path: Path) -> Path:
    project = tmp_path / "sample-project"
    project.mkdir()
    (project / "requirements.txt").write_text(
        "requests==2.25.1\nurllib3\n",
        encoding="utf-8",
    )
    return project


@pytest.fixture()
def completed_scan(container: AppContainer, sample_project: Path) -> Scan:
    scan = container.scan_service.create_scan(
        source_type="local",
        project_name="sample-project",
        source_reference=str(sample_project),
        metadata={"project_root": str(sample_project)},
    )
    asyncio.run(container.scan_service.execute(scan.id))
    result = container.scan_service.get_scan(scan.id, full=True)
    assert result is not None
    return result


@pytest.fixture()
def client(container: AppContainer, settings: AppSettings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(settings=settings, container=container)) as test_client:
        yield test_client


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()
