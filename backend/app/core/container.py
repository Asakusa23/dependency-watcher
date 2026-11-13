from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import AppSettings
from app.core.rate_limit import TokenBucketLimiter
from app.database.session import Database
from app.reporting.report_service import ReportService
from app.risk_engine.engine import RiskEngine
from app.sbom.generator import SbomGenerator
from app.scanners.github import GitHubSource
from app.scanners.scanner import ProjectScanner
from app.services.comparison_service import ComparisonService
from app.services.health_service import DependencyHealthEngine, RegistryClient
from app.services.remediation_service import RemediationService
from app.services.scan_service import ScanService
from app.services.settings_service import SettingsService
from app.vulnerability_engine.cache import CacheStore
from app.vulnerability_engine.engine import VulnerabilityEngine
from app.vulnerability_engine.nvd import NvdClient
from app.vulnerability_engine.osv import OsvClient


@dataclass
class AppContainer:
    settings: AppSettings
    database: Database
    cache: CacheStore
    settings_service: SettingsService
    scan_service: ScanService
    report_service: ReportService
    comparison_service: ComparisonService
    remediation_service: RemediationService
    sbom_generator: SbomGenerator
    global_limiter: TokenBucketLimiter
    scan_limiter: TokenBucketLimiter


def build_container(settings: AppSettings) -> AppContainer:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    database = Database(settings.database_url)
    database.create_all()
    cache = CacheStore(settings.cache_path)
    settings_service = SettingsService(settings)
    registry_client = RegistryClient(settings, cache)
    osv_client = OsvClient(settings, cache)
    nvd_client = NvdClient(settings, cache)
    vulnerability_engine = VulnerabilityEngine(settings, cache, osv=osv_client, nvd=nvd_client)
    health_engine = DependencyHealthEngine(settings, registry_client)
    risk_engine = RiskEngine()
    remediation = RemediationService()
    scan_service = ScanService(
        settings,
        database,
        cache=cache,
        scanner=ProjectScanner(settings),
        vulnerability_engine=vulnerability_engine,
        health_engine=health_engine,
        risk_engine=risk_engine,
        github_source=GitHubSource(settings),
    )
    return AppContainer(
        settings=settings,
        database=database,
        cache=cache,
        settings_service=settings_service,
        scan_service=scan_service,
        report_service=ReportService(remediation),
        comparison_service=ComparisonService(),
        remediation_service=remediation,
        sbom_generator=SbomGenerator(),
        global_limiter=TokenBucketLimiter(settings.rate_limit_per_minute, settings.rate_limit_per_minute / 60),
        scan_limiter=TokenBucketLimiter(settings.scan_rate_limit_per_hour, settings.scan_rate_limit_per_hour / 3600),
    )
