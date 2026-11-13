from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from app.core.config import AppSettings


PERSISTED_FIELDS = (
    "allow_local_paths",
    "enable_osv",
    "enable_registry",
    "enable_nvd",
    "enable_github",
    "http_timeout_seconds",
    "cache_ttl_seconds",
)


class SettingsService:
    """Loads and persists non-secret scanner settings; API keys are masked in responses."""

    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self._load()

    def _load(self) -> None:
        path = self.settings.settings_path
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        for field in PERSISTED_FIELDS:
            if field in data:
                setattr(self.settings, field, data[field])
        if data.get("nvd_api_key"):
            self.settings.nvd_api_key = str(data["nvd_api_key"])
        if data.get("github_token"):
            self.settings.github_token = str(data["github_token"])

    def public(self) -> dict[str, Any]:
        return self.settings.settings_public

    def update(self, payload: dict[str, Any]) -> dict[str, Any]:
        for field in PERSISTED_FIELDS:
            if field in payload and payload[field] is not None:
                value = payload[field]
                if field.startswith("enable_") or field == "allow_local_paths":
                    value = bool(value)
                elif field == "http_timeout_seconds":
                    value = max(3.0, min(120.0, float(value)))
                elif field == "cache_ttl_seconds":
                    value = max(60, min(7 * 24 * 3600, int(value)))
                setattr(self.settings, field, value)
        if payload.get("nvd_api_key"):
            self.settings.nvd_api_key = str(payload["nvd_api_key"]).strip()[:500]
        if payload.get("github_token"):
            self.settings.github_token = str(payload["github_token"]).strip()[:500]
        if payload.get("clear_nvd_api_key"):
            self.settings.nvd_api_key = ""
        if payload.get("clear_github_token"):
            self.settings.github_token = ""
        self._save()
        return self.public()

    def _save(self) -> None:
        path = self.settings.settings_path
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {field: getattr(self.settings, field) for field in PERSISTED_FIELDS}
        if self.settings.nvd_api_key:
            data["nvd_api_key"] = self.settings.nvd_api_key
        if self.settings.github_token:
            data["github_token"] = self.settings.github_token
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(temp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
