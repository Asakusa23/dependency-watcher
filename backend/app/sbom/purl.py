from __future__ import annotations

from urllib.parse import quote


_PURL_TYPES = {
    "PyPI": "pypi",
    "npm": "npm",
    "Maven": "maven",
    "crates.io": "cargo",
    "Go": "golang",
    "NuGet": "nuget",
}


def package_url(ecosystem: str, name: str, version: str = "") -> str:
    purl_type = _PURL_TYPES.get(ecosystem, quote(ecosystem.lower(), safe=""))
    encoded_version = f"@{quote(version, safe='')}" if version else ""
    if ecosystem == "Maven" and ":" in name:
        group, artifact = name.split(":", 1)
        namespace = "/".join(quote(part, safe="") for part in group.split("."))
        return f"pkg:{purl_type}/{namespace}/{quote(artifact, safe='')}{encoded_version}"
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        scope, package = name.split("/", 1)
        return f"pkg:{purl_type}/{quote(scope, safe='')}/{quote(package, safe='')}{encoded_version}"
    return f"pkg:{purl_type}/{quote(name, safe='')}{encoded_version}"
