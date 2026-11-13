from __future__ import annotations

import re
from functools import lru_cache

try:
    from packaging.version import InvalidVersion, Version
except Exception:  # pragma: no cover
    Version = None  # type: ignore
    InvalidVersion = Exception  # type: ignore


_VERSION_CLEAN_RE = re.compile(r"^[vV=\s]+")
_TOKEN_RE = re.compile(r"(\d+|[A-Za-z]+)")


def normalize_version(value: str | None) -> str:
    if not value:
        return ""
    cleaned = value.strip()
    cleaned = _VERSION_CLEAN_RE.sub("", cleaned)
    cleaned = cleaned.split("+", 1)[0]
    return cleaned


@lru_cache(maxsize=4096)
def _pep440(value: str):
    if Version is None:
        return None
    try:
        return Version(value)
    except InvalidVersion:
        return None


def compare_versions(left: str | None, right: str | None) -> int | None:
    """Compare versions. Returns -1/0/1, or None when comparison is not meaningful."""
    a = normalize_version(left)
    b = normalize_version(right)
    if not a or not b:
        return None
    if a == b:
        return 0
    pa, pb = _pep440(a), _pep440(b)
    if pa is not None and pb is not None:
        return (pa > pb) - (pa < pb)
    return _loose_compare(a, b)


def _loose_compare(a: str, b: str) -> int | None:
    ta = _TOKEN_RE.findall(a.lower())
    tb = _TOKEN_RE.findall(b.lower())
    if not ta or not tb:
        return None
    for idx in range(max(len(ta), len(tb))):
        xa = ta[idx] if idx < len(ta) else "0"
        xb = tb[idx] if idx < len(tb) else "0"
        if xa.isdigit() and xb.isdigit():
            ia, ib = int(xa), int(xb)
            if ia != ib:
                return 1 if ia > ib else -1
        elif xa != xb:
            return 1 if xa > xb else -1
    return 0


def is_newer_version(current: str | None, latest: str | None) -> bool:
    result = compare_versions(latest, current)
    return result == 1


def major_version(value: str | None) -> int | None:
    normalized = normalize_version(value)
    if not normalized:
        return None
    match = re.match(r"^(\d+)", normalized)
    return int(match.group(1)) if match else None


def is_major_upgrade(current: str | None, target: str | None) -> bool:
    a, b = major_version(current), major_version(target)
    return a is not None and b is not None and b > a


def is_pinned_version(value: str | None, ecosystem: str) -> bool:
    if not value:
        return False
    spec = value.strip()
    if ecosystem == "PyPI":
        return bool(
            re.match(r"^===?\s*[A-Za-z0-9_.+!-]+$", spec)
            or re.match(r"^[0-9][A-Za-z0-9_.+!-]*$", spec)
        )
    if ecosystem in {"npm", "crates.io"}:
        return bool(re.match(r"^\d+(\.\d+)*([-+][A-Za-z0-9_.-]+)?$", spec))
    if ecosystem == "Maven":
        return bool(re.match(r"^[A-Za-z0-9_.+!-]+$", spec)) and not spec.startswith("${")
    return False


def extract_pinned_version(spec: str | None, ecosystem: str) -> str:
    if not spec:
        return ""
    value = spec.strip()
    if ecosystem == "PyPI":
        for prefix in ("===", "=="):
            if value.startswith(prefix):
                candidate = value[len(prefix):].strip()
                if "," not in candidate and "*" not in candidate:
                    return candidate.split(";", 1)[0].strip()
        return ""
    if ecosystem == "npm":
        candidate = value.lstrip("v")
        if re.match(r"^\d+(\.\d+)*([-+][A-Za-z0-9_.-]+)?$", candidate):
            return candidate
        return ""
    return value if is_pinned_version(value, ecosystem) else ""
