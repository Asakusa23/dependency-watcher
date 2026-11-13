from __future__ import annotations

import pytest

from app.core.versions import (
    compare_versions,
    extract_pinned_version,
    is_major_upgrade,
    is_newer_version,
    is_pinned_version,
    normalize_version,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("==1.2.3", "1.2.3"),
        ("===1.2.3", "1.2.3"),
        ("==1.2.3; python_version >= '3.11'", "1.2.3"),
        ("==1.*", ""),
        ("~=1.2", ""),
        (">=1.2,<2", ""),
    ],
)
def test_extract_pypi_pinned_version(value: str, expected: str) -> None:
    assert extract_pinned_version(value, "PyPI") == expected


@pytest.mark.parametrize(
    ("value", "ecosystem", "expected"),
    [
        ("1.2.3", "PyPI", True),
        ("1.2.3", "npm", True),
        ("^1.2.3", "npm", False),
        ("=1.2.3", "crates.io", False),
        ("1.2.3", "crates.io", True),
        ("1.2.3", "Maven", True),
        ("${spring.version}", "Maven", False),
    ],
)
def test_pinning(value: str, ecosystem: str, expected: bool) -> None:
    assert is_pinned_version(value, ecosystem) is expected


def test_version_comparison_falls_back_for_non_pep440() -> None:
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("v2.0.0", "1.9.9") == 1
    assert compare_versions("2024.01", "2024.02") == -1
    assert compare_versions("", "1.0") is None
    assert is_newer_version("1.0.0", "1.0.1") is True
    assert is_major_upgrade("1.9.0", "2.0.0") is True


def test_normalize_version() -> None:
    assert normalize_version("==1.2.3+build.4") == "1.2.3"
    assert normalize_version("  v2.0.0 ") == "2.0.0"
