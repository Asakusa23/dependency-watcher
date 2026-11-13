from __future__ import annotations

import socket
import stat
import zipfile
from pathlib import Path

import pytest

from app.core.security import (
    SecurityError,
    ensure_within,
    normalize_project_root,
    safe_extract_zip,
    validate_github_url,
    validate_hostname_addresses,
    validate_outbound_url,
)

from .conftest import make_zip


def test_validate_github_url_accepts_repository_and_ref() -> None:
    owner, repo, ref = validate_github_url(
        "https://github.com/example/project/tree/main/subdir",
        ("github.com",),
    )
    assert (owner, repo, ref) == ("example", "project", "main/subdir")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/project",
        "https://evil.example/example/project",
        "https://user:pass@github.com/example/project",
        "https://github.com/example",
        "https://github.com/../project",
        "https://github.com:8443/example/project",
        "https://github.com/example/project/tree/..%2F..%2Fetc",
    ],
)
def test_validate_github_url_rejects_unsafe_inputs(url: str) -> None:
    with pytest.raises(SecurityError):
        validate_github_url(url, ("github.com",))


def test_validate_hostname_rejects_loopback() -> None:
    with pytest.raises(SecurityError):
        validate_hostname_addresses("127.0.0.1")


def test_validate_outbound_url_rejects_private_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("10.0.0.1", 443))])
    with pytest.raises(SecurityError):
        validate_outbound_url("https://github.com/example/project", ("github.com",))


def test_safe_zip_extraction_normalizes_single_root(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    archive.write_bytes(make_zip({"project/requirements.txt": "requests==2.25.1\n"}))
    extracted = safe_extract_zip(
        archive,
        tmp_path / "out",
        max_files=10,
        max_total_bytes=10_000,
        max_file_bytes=10_000,
    )
    assert extracted.root.name == "project"
    assert extracted.files_extracted == 1
    assert (extracted.root / "requirements.txt").is_file()


@pytest.mark.parametrize("name", ["../escape.txt", "/absolute.txt", "C:/windows.txt", "a/../../escape.txt"])
def test_safe_zip_rejects_traversal(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "bad.zip"
    archive.write_bytes(make_zip({name: "secret"}))
    with pytest.raises(SecurityError):
        safe_extract_zip(
            archive,
            tmp_path / "out",
            max_files=10,
            max_total_bytes=10_000,
            max_file_bytes=10_000,
        )


def test_safe_zip_rejects_symlink(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "target")
    with pytest.raises(SecurityError):
        safe_extract_zip(
            archive,
            tmp_path / "out",
            max_files=10,
            max_total_bytes=10_000,
            max_file_bytes=10_000,
        )


def test_safe_zip_enforces_limits(tmp_path: Path) -> None:
    archive = tmp_path / "large.zip"
    archive.write_bytes(make_zip({"a.txt": "x" * 50, "b.txt": "y" * 50}))
    with pytest.raises(SecurityError):
        safe_extract_zip(
            archive,
            tmp_path / "out",
            max_files=1,
            max_total_bytes=10_000,
            max_file_bytes=10_000,
        )


def test_path_boundaries(tmp_path: Path) -> None:
    root = tmp_path / "root"
    inside = root / "a" / "b.txt"
    inside.parent.mkdir(parents=True)
    inside.write_text("ok", encoding="utf-8")
    assert ensure_within(root, inside) == inside.resolve()
    with pytest.raises(SecurityError):
        ensure_within(root, tmp_path / "outside.txt")
    assert normalize_project_root(root) == root
