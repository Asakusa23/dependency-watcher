from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx
from defusedxml import ElementTree as DefusedET

from app.core.config import AppSettings
from app.core.versions import is_newer_version
from app.vulnerability_engine.cache import CacheStore


@dataclass
class RegistryInfo:
    latest_version: str = ""
    license: str = ""
    deprecated: bool = False
    deprecation_reason: str = ""
    release_date: str = ""
    source_url: str = ""
    error: str = ""


@dataclass
class HealthResult:
    latest_version: str = ""
    license: str = ""
    outdated: bool = False
    deprecated: bool = False
    deprecation_reason: str = ""
    release_date: str = ""
    health_status: str = "UNKNOWN"
    error: str = ""


class RegistryClient:
    """Registry metadata client for latest versions, licenses and explicit deprecations."""

    def __init__(self, settings: AppSettings, cache: CacheStore, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self.cache = cache
        self._client = client

    async def get(self, ecosystem: str, name: str) -> RegistryInfo:
        cache_key = f"registry:{ecosystem}:{name.lower()}"
        cached = self.cache.get(cache_key)
        if isinstance(cached, dict):
            return RegistryInfo(**cached)
        if not self.settings.enable_registry:
            return RegistryInfo(error="Registry source is disabled in settings")
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds),
            follow_redirects=False,
            headers={
                "User-Agent": "DependencyWatcher/1.0 (+https://github.com/dependency-watcher)",
                "Accept": "application/json, application/xml;q=0.9, */*;q=0.5",
            },
        )
        try:
            if ecosystem == "PyPI":
                info = await self._pypi(client, name)
            elif ecosystem == "npm":
                info = await self._npm(client, name)
            elif ecosystem == "Maven":
                info = await self._maven(client, name)
            elif ecosystem == "crates.io":
                info = await self._crates(client, name)
            else:
                info = RegistryInfo(error="Unsupported ecosystem for registry lookup")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            info = RegistryInfo(error=f"Registry lookup failed: {type(exc).__name__}")
        except Exception as exc:  # malformed upstream payloads must not abort scans
            info = RegistryInfo(error=f"Registry lookup failed: {type(exc).__name__}")
        finally:
            if owns_client:
                await client.aclose()
        if not info.error:
            self.cache.set(cache_key, info.__dict__, self.settings.cache_ttl_seconds)
        return info

    async def _pypi(self, client: httpx.AsyncClient, name: str) -> RegistryInfo:
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/json"
        response = await self._request(client, url)
        data = response.json()
        info = data.get("info", {}) or {}
        latest = str(info.get("version", ""))
        license_value = _clean_license(info.get("license_expression") or info.get("license") or "")
        if not license_value:
            for classifier in info.get("classifiers", []) or []:
                if isinstance(classifier, str) and classifier.startswith("License ::"):
                    license_value = _clean_license(classifier.split("::")[-1].strip())
                    break
        release_date = ""
        releases = data.get("releases", {}) or {}
        entries = releases.get(latest) or []
        if entries and isinstance(entries[0], dict):
            release_date = str(entries[0].get("upload_time_iso_8601") or entries[0].get("upload_time") or "")
        deprecated = bool(info.get("yanked"))
        reason = str(info.get("yanked_reason") or "") if deprecated else ""
        return RegistryInfo(
            latest_version=latest,
            license=license_value,
            deprecated=deprecated,
            deprecation_reason=reason or ("Latest release is yanked" if deprecated else ""),
            release_date=release_date,
            source_url=f"https://pypi.org/project/{quote(name, safe='')}/",
        )

    async def _npm(self, client: httpx.AsyncClient, name: str) -> RegistryInfo:
        url = f"https://registry.npmjs.org/{quote(name, safe='@')}"
        headers = {"Accept": "application/vnd.npm.install-v1+json"}
        response = await self._request(client, url, headers=headers, max_bytes=30 * 1024 * 1024)
        data = response.json()
        tags = data.get("dist-tags", {}) or {}
        latest = str(tags.get("latest", ""))
        versions = data.get("versions", {}) or {}
        version_data = versions.get(latest, {}) if isinstance(versions, dict) else {}
        license_value = _clean_license(version_data.get("license") or "")
        deprecated_reason = str(version_data.get("deprecated") or "") if isinstance(version_data, dict) else ""
        times = data.get("time", {}) or {}
        release_date = str(times.get(latest, "")) if isinstance(times, dict) else ""
        return RegistryInfo(
            latest_version=latest,
            license=license_value,
            deprecated=bool(deprecated_reason),
            deprecation_reason=deprecated_reason[:1000],
            release_date=release_date,
            source_url=f"https://www.npmjs.com/package/{name}",
        )

    async def _maven(self, client: httpx.AsyncClient, name: str) -> RegistryInfo:
        if ":" not in name:
            return RegistryInfo(error="Malformed Maven coordinate")
        group, artifact = name.split(":", 1)
        if not re.match(r"^[A-Za-z0-9_.-]+$", group) or not re.match(r"^[A-Za-z0-9_.-]+$", artifact):
            return RegistryInfo(error="Unsafe Maven coordinate")
        group_path = group.replace(".", "/")
        url = f"https://repo1.maven.org/maven2/{quote(group_path, safe='/')}/{quote(artifact, safe='')}/maven-metadata.xml"
        response = await self._request(client, url, max_bytes=5 * 1024 * 1024)
        root = DefusedET.fromstring(response.content)
        latest = ""
        release = ""
        last_updated = ""
        version_nodes = []
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag == "latest" and node.text:
                latest = node.text.strip()
            elif tag == "release" and node.text:
                release = node.text.strip()
            elif tag == "lastUpdated" and node.text:
                last_updated = node.text.strip()
            elif tag == "version" and node.text:
                version_nodes.append(node.text.strip())
        latest = release or latest or (version_nodes[-1] if version_nodes else "")
        return RegistryInfo(
            latest_version=latest,
            release_date=last_updated,
            source_url=f"https://search.maven.org/artifact/{group}/{artifact}",
        )

    async def _crates(self, client: httpx.AsyncClient, name: str) -> RegistryInfo:
        url = f"https://crates.io/api/v1/crates/{quote(name, safe='')}"
        response = await self._request(client, url)
        data = response.json()
        crate = data.get("crate", {}) or {}
        latest = str(crate.get("max_stable_version") or crate.get("max_version") or crate.get("newest_version") or "")
        return RegistryInfo(
            latest_version=latest,
            license=_clean_license(crate.get("license") or ""),
            release_date=str(crate.get("updated_at") or ""),
            source_url=f"https://crates.io/crates/{name}",
        )

    async def _request(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str] | None = None,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> httpx.Response:
        last_status = None
        for attempt in range(2):
            response = await client.get(url, headers=headers)
            last_status = response.status_code
            if response.status_code == 429 or response.status_code >= 500:
                await asyncio.sleep(0.4 * (attempt + 1))
                continue
            if response.status_code >= 400:
                raise ValueError(f"HTTP {response.status_code}")
            if len(response.content) > max_bytes:
                raise ValueError("Registry response exceeded size limit")
            return response
        raise ValueError(f"HTTP {last_status}")


class DependencyHealthEngine:
    def __init__(
        self,
        settings: AppSettings,
        registry: RegistryClient,
    ) -> None:
        self.settings = settings
        self.registry = registry

    async def check(self, dependencies: list[tuple[str, str, str, str]]) -> dict[str, HealthResult]:
        """dependencies: (key, name, version, ecosystem)."""
        semaphore = asyncio.Semaphore(8)
        results: dict[str, HealthResult] = {}

        async def _check(key: str, name: str, version: str, ecosystem: str) -> None:
            async with semaphore:
                registry_info = await self.registry.get(ecosystem, name)
            if registry_info.error:
                results[key] = HealthResult(error=registry_info.error)
                return
            outdated = bool(version and registry_info.latest_version and is_newer_version(version, registry_info.latest_version))
            if not version:
                status = "UNPINNED"
            elif registry_info.deprecated:
                status = "DEPRECATED"
            elif outdated:
                status = "OUTDATED"
            else:
                status = "CURRENT"
            results[key] = HealthResult(
                latest_version=registry_info.latest_version,
                license=registry_info.license,
                outdated=outdated,
                deprecated=registry_info.deprecated,
                deprecation_reason=registry_info.deprecation_reason,
                release_date=registry_info.release_date,
                health_status=status,
            )

        await asyncio.gather(*[_check(*item) for item in dependencies])
        return results


def _clean_license(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if text.upper() in {"UNKNOWN", "NONE", "NOASSERTION", "UNLICENSED", "PROPRIETARY"}:
        return ""
    text = re.sub(r"\s+", " ", text)
    return text[:250]
