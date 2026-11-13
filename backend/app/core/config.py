from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class AppSettings:
    data_dir: Path
    database_url: str
    cache_path: Path
    settings_path: Path
    work_dir: Path
    allow_local_paths: bool = True
    enable_osv: bool = True
    enable_registry: bool = True
    enable_nvd: bool = False
    enable_github: bool = True
    osv_api_url: str = "https://api.osv.dev/v1"
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""
    github_token: str = ""
    http_timeout_seconds: float = 20.0
    max_upload_bytes: int = 50 * 1024 * 1024
    max_archive_files: int = 10_000
    max_extracted_bytes: int = 250 * 1024 * 1024
    max_project_files: int = 50_000
    max_dependencies: int = 20_000
    max_dependency_file_bytes: int = 20 * 1024 * 1024
    cache_ttl_seconds: int = 6 * 60 * 60
    rate_limit_per_minute: int = 180
    scan_rate_limit_per_hour: int = 60
    github_hosts: tuple[str, ...] = ("github.com", "www.github.com", "api.github.com", "codeload.github.com")
    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    )
    frontend_dist: Path | None = None
    extra: dict = field(default_factory=dict)

    @property
    def settings_public(self) -> dict:
        return {
            "allow_local_paths": self.allow_local_paths,
            "enable_osv": self.enable_osv,
            "enable_registry": self.enable_registry,
            "enable_nvd": self.enable_nvd,
            "enable_github": self.enable_github,
            "http_timeout_seconds": self.http_timeout_seconds,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "nvd_api_key_configured": bool(self.nvd_api_key),
            "github_token_configured": bool(self.github_token),
        }


def build_settings(data_dir: str | Path | None = None) -> AppSettings:
    raw = data_dir or os.environ.get("DW_DATA_DIR") or (PROJECT_ROOT / "data")
    base = Path(raw).expanduser().resolve()
    base.mkdir(parents=True, exist_ok=True)
    work = base / "work"
    work.mkdir(parents=True, exist_ok=True)
    database_url = os.environ.get("DW_DATABASE_URL") or f"sqlite:///{(base / 'dependency_watcher.db').as_posix()}"
    frontend_env = os.environ.get("DW_FRONTEND_DIST")
    return AppSettings(
        data_dir=base,
        database_url=database_url,
        cache_path=base / "cache.db",
        settings_path=base / "settings.json",
        work_dir=work,
        allow_local_paths=_env_bool("DW_ALLOW_LOCAL_PATHS", True),
        enable_osv=_env_bool("DW_ENABLE_OSV", True),
        enable_registry=_env_bool("DW_ENABLE_REGISTRY", True),
        enable_nvd=_env_bool("DW_ENABLE_NVD", False),
        enable_github=_env_bool("DW_ENABLE_GITHUB", True),
        nvd_api_key=os.environ.get("DW_NVD_API_KEY", ""),
        github_token=os.environ.get("DW_GITHUB_TOKEN", ""),
        http_timeout_seconds=float(os.environ.get("DW_HTTP_TIMEOUT", "20")),
        max_upload_bytes=_env_int("DW_MAX_UPLOAD_BYTES", 50 * 1024 * 1024),
        max_archive_files=_env_int("DW_MAX_ARCHIVE_FILES", 10_000),
        max_extracted_bytes=_env_int("DW_MAX_EXTRACTED_BYTES", 250 * 1024 * 1024),
        max_project_files=_env_int("DW_MAX_PROJECT_FILES", 50_000),
        max_dependencies=_env_int("DW_MAX_DEPENDENCIES", 20_000),
        max_dependency_file_bytes=_env_int("DW_MAX_DEPENDENCY_FILE_BYTES", 20 * 1024 * 1024),
        cache_ttl_seconds=_env_int("DW_CACHE_TTL", 6 * 60 * 60),
        rate_limit_per_minute=_env_int("DW_RATE_LIMIT_PER_MINUTE", 180),
        scan_rate_limit_per_hour=_env_int("DW_SCAN_RATE_LIMIT_PER_HOUR", 60),
        frontend_dist=Path(frontend_env).resolve() if frontend_env else None,
    )
