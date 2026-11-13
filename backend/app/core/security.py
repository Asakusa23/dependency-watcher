from __future__ import annotations

import ipaddress
import re
import socket
import stat
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable
from urllib.parse import unquote, urlparse

from fastapi import HTTPException


class SecurityError(ValueError):
    """Raised when input violates a security boundary."""


GITHUB_OWNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
GITHUB_REF_RE = re.compile(r"^[A-Za-z0-9_.\-/]{1,200}$")


def validate_github_url(url: str, allowed_hosts: Iterable[str]) -> tuple[str, str, str | None]:
    parsed = urlparse(url.strip())
    if parsed.scheme != "https":
        raise SecurityError("Only HTTPS GitHub URLs are allowed")
    if parsed.username or parsed.password:
        raise SecurityError("Credentials in URLs are not allowed")
    host = (parsed.hostname or "").lower()
    allow = {h.lower() for h in allowed_hosts}
    if host not in allow:
        raise SecurityError("GitHub host is not allowlisted")
    if parsed.port not in (None, 443):
        raise SecurityError("Only the default HTTPS port is allowed")
    decoded_path = unquote(parsed.path).replace("\\", "/")
    segments = [part for part in decoded_path.split("/") if part]
    if any(part in {".", ".."} for part in segments):
        raise SecurityError("Path traversal segments are not allowed in GitHub URLs")
    parts = segments
    if len(parts) < 2:
        raise SecurityError("GitHub URL must point to a repository (owner/repo)")
    owner, repo = parts[0], parts[1]
    if owner in {".", ".."} or repo in {".", ".."}:
        raise SecurityError("Invalid GitHub owner or repository name")
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not GITHUB_OWNER_RE.match(owner) or not GITHUB_OWNER_RE.match(repo):
        raise SecurityError("Invalid GitHub owner or repository name")
    ref: str | None = None
    if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
        ref = "/".join(parts[3:])
        if not GITHUB_REF_RE.match(ref):
            raise SecurityError("Invalid GitHub ref")
    return owner, repo, ref


def _resolve_public_addresses(host: str, port: int = 443) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SecurityError("GitHub host could not be resolved") from exc
    addresses: list[str] = []
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise SecurityError("Invalid resolved address") from exc
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise SecurityError("Resolved address is not publicly routable")
        addresses.append(address)
    if not addresses:
        raise SecurityError("GitHub host resolved to no addresses")
    return addresses


def validate_outbound_url(url: str, allowed_hosts: Iterable[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SecurityError("Only HTTPS outbound URLs are allowed")
    host = (parsed.hostname or "").lower()
    if host not in {h.lower() for h in allowed_hosts}:
        raise SecurityError("Outbound host is not allowlisted")
    if parsed.username or parsed.password:
        raise SecurityError("Credentials in URLs are not allowed")
    _resolve_public_addresses(host, parsed.port or 443)


def validate_hostname_addresses(host: str, port: int = 443) -> None:
    _resolve_public_addresses(host, port)


@dataclass(frozen=True)
class ExtractedProject:
    root: Path
    files_extracted: int
    bytes_extracted: int


def _safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise SecurityError(f"Absolute path in archive: {name}")
    path = PurePosixPath(normalized)
    if any(part in {"..", ""} for part in path.parts):
        raise SecurityError(f"Path traversal attempt in archive: {name}")
    return path


def safe_extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    max_files: int,
    max_total_bytes: int,
    max_file_bytes: int | None = None,
) -> ExtractedProject:
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    total_written = 0
    extracted_files = 0
    try:
        zf = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        raise SecurityError("Uploaded file is not a valid ZIP archive") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise SecurityError(f"Archive contains more than {max_files} entries")
        for info in infos:
            member = _safe_member_path(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise SecurityError(f"Symbolic links are not allowed: {info.filename}")
            if info.flag_bits & 0x1:
                raise SecurityError("Encrypted archives are not supported")
            target = destination.joinpath(*member.parts)
            resolved = target.resolve()
            if destination != resolved and destination not in resolved.parents:
                raise SecurityError(f"Archive entry escapes destination: {info.filename}")
            if info.is_dir():
                resolved.mkdir(parents=True, exist_ok=True)
                continue
            if info.file_size > (max_file_bytes or max_total_bytes):
                raise SecurityError("Archive entry exceeds size limit")
            total_written += info.file_size
            if total_written > max_total_bytes:
                raise SecurityError("Extracted archive exceeds total size limit")
            if info.compress_size > 0 and info.file_size > 1024 * 1024:
                ratio = info.file_size / info.compress_size
                if ratio > 500:
                    raise SecurityError("Suspicious compression ratio (possible zip bomb)")
            resolved.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as source, open(resolved, "wb") as out:
                written = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size or total_written - info.file_size + written > max_total_bytes:
                        raise SecurityError("Archive expanded beyond declared size")
                    out.write(chunk)
            extracted_files += 1
    return ExtractedProject(
        root=_unwrap_single_root(destination),
        files_extracted=extracted_files,
        bytes_extracted=total_written,
    )


def _unwrap_single_root(destination: Path) -> Path:
    entries = [entry for entry in destination.iterdir() if entry.name not in {"__MACOSX"}]
    directories = [entry for entry in entries if entry.is_dir() and not entry.is_symlink()]
    files = [entry for entry in entries if entry.is_file()]
    if len(directories) == 1 and not files:
        return directories[0]
    return destination


def normalize_project_root(destination: Path) -> Path:
    resolved = destination.resolve()
    if not resolved.is_dir():
        raise SecurityError("Project root is not a directory")
    return resolved


def new_work_dir(base: Path, scan_id: str | None = None) -> Path:
    identifier = scan_id or uuid.uuid4().hex
    path = (base / identifier).resolve()
    base_resolved = base.resolve()
    if base_resolved not in path.parents and path != base_resolved:
        raise SecurityError("Invalid work directory")
    path.mkdir(parents=True, exist_ok=False)
    return path


def ensure_within(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    resolved = candidate.resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise SecurityError("Path escapes allowed root")
    return resolved


def http_error(status_code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail=detail)
