from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from urllib.parse import quote

import httpx

from app.core.config import AppSettings
from app.core.security import (
    ExtractedProject,
    SecurityError,
    safe_extract_zip,
    validate_github_url,
    validate_outbound_url,
)


class GitHubSource:
    def __init__(self, settings: AppSettings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def download(self, repository_url: str, destination: Path) -> ExtractedProject:
        if not self.settings.enable_github:
            raise SecurityError("GitHub source is disabled in settings")
        owner, repo, ref = validate_github_url(repository_url, self.settings.github_hosts)
        destination.mkdir(parents=True, exist_ok=True)
        archive_path = destination / "repository.zip"
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "DependencyWatcher/1.0"}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"

        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": "DependencyWatcher/1.0"},
        )
        try:
            if not ref:
                api_url = f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}"
                payload = await self._get_json(client, api_url, headers)
                ref = str(payload.get("default_branch") or "")
                if not ref:
                    raise SecurityError("GitHub repository has no default branch")
            archive_url = f"https://codeload.github.com/{owner}/{repo}/zip/{quote(ref, safe='/')}"
            await self._download_file(client, archive_url, archive_path, headers)
        finally:
            if owns_client:
                await client.aclose()

        try:
            return await asyncio.to_thread(
                safe_extract_zip,
                archive_path,
                destination / "project",
                max_files=self.settings.max_archive_files,
                max_total_bytes=self.settings.max_extracted_bytes,
                max_file_bytes=self.settings.max_extracted_bytes,
            )
        finally:
            archive_path.unlink(missing_ok=True)

    async def _get_json(self, client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> dict:
        validate_outbound_url(url, self.settings.github_hosts)
        response = await client.get(url, headers=headers)
        if response.status_code >= 400:
            raise SecurityError(f"GitHub API returned HTTP {response.status_code}")
        if len(response.content) > 2 * 1024 * 1024:
            raise SecurityError("GitHub API response exceeded the metadata size limit")
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise SecurityError("GitHub API returned invalid JSON") from exc

    async def _download_file(
        self,
        client: httpx.AsyncClient,
        url: str,
        destination: Path,
        headers: dict[str, str],
        redirects: int = 0,
    ) -> None:
        if redirects > 3:
            raise SecurityError("Too many redirects while downloading GitHub archive")
        validate_outbound_url(url, self.settings.github_hosts)
        request_headers = dict(headers)
        request_headers["Accept"] = "application/zip"
        async with client.stream("GET", url, headers=request_headers) as response:
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise SecurityError("GitHub returned a redirect without a location")
                target = httpx.URL(url).join(location)
                target_str = str(target)
                await self._download_file(client, target_str, destination, headers, redirects + 1)
                return
            if response.status_code >= 400:
                raise SecurityError(f"GitHub archive download failed with HTTP {response.status_code}")
            expected = response.headers.get("content-length")
            if expected and int(expected) > self.settings.max_upload_bytes:
                raise SecurityError("GitHub archive exceeds the configured size limit")
            written = 0
            with open(destination, "wb") as output:
                async for chunk in response.aiter_bytes(1024 * 256):
                    written += len(chunk)
                    if written > self.settings.max_upload_bytes:
                        raise SecurityError("GitHub archive exceeded the configured size limit")
                    output.write(chunk)
            if written == 0:
                raise SecurityError("GitHub returned an empty archive")
