from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanCreateRequest(BaseModel):
    source_type: Literal["local", "github"]
    path: str | None = Field(default=None, max_length=4000)
    repository_url: str | None = Field(default=None, max_length=2000)
    project_name: str | None = Field(default=None, max_length=255)

    @field_validator("path", "repository_url", "project_name")
    @classmethod
    def strip_value(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class SettingsUpdateRequest(BaseModel):
    allow_local_paths: bool | None = None
    enable_osv: bool | None = None
    enable_registry: bool | None = None
    enable_nvd: bool | None = None
    enable_github: bool | None = None
    http_timeout_seconds: float | None = Field(default=None, ge=3, le=120)
    cache_ttl_seconds: int | None = Field(default=None, ge=60, le=604800)
    nvd_api_key: str | None = Field(default=None, max_length=500)
    github_token: str | None = Field(default=None, max_length=500)
    clear_nvd_api_key: bool = False
    clear_github_token: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    sources: dict
