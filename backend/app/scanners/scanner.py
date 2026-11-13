from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import AppSettings
from app.parsers.base import ParsedDependency
from app.parsers.registry import ParserRegistry
from app.sbom.purl import package_url


IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "target",
    "vendor",
    "coverage",
    ".next",
    ".turbo",
}


@dataclass
class ScanResult:
    dependencies: list[ParsedDependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dependency_files: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    project_files_scanned: int = 0
    project_type: str = "unknown"


class ProjectScanner:
    def __init__(self, settings: AppSettings, registry: ParserRegistry | None = None) -> None:
        self.settings = settings
        self.registry = registry or ParserRegistry()

    def scan(self, root: Path) -> ScanResult:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("Scan root is not a directory")
        result = ScanResult()
        discovered: list[Path] = []
        file_count = 0
        try:
            for current, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = sorted(
                    d for d in dirnames if d not in IGNORED_DIRECTORIES and not (Path(current) / d).is_symlink()
                )
                for filename in sorted(filenames):
                    file_count += 1
                    if file_count > self.settings.max_project_files:
                        raise ValueError(f"Project exceeds the {self.settings.max_project_files} file scan limit")
                    path = Path(current) / filename
                    if path.is_symlink() or not path.is_file():
                        continue
                    if self.registry.detect(path) is not None:
                        try:
                            if path.stat().st_size > self.settings.max_dependency_file_bytes:
                                result.warnings.append(
                                    f"Skipped oversized dependency file: {path.relative_to(root).as_posix()}"
                                )
                                continue
                        except OSError:
                            continue
                        discovered.append(path)
        except OSError as exc:
            result.errors.append(f"File discovery failed: {exc}")
        result.project_files_scanned = file_count

        parsed: list[ParsedDependency] = []
        for path in discovered:
            parser = self.registry.detect(path)
            if parser is None:
                continue
            rel = path.relative_to(root).as_posix()
            try:
                parser_result = parser.parse(path, root)
                parsed.extend(parser_result.dependencies)
                result.warnings.extend(parser_result.warnings)
                result.dependency_files.append(rel)
            except Exception as exc:  # defensive: one malformed file must not abort a scan
                result.errors.append(f"{parser.name} failed for {rel}: {exc}")
        if not discovered:
            result.warnings.append("No supported dependency files were found")

        merged = self._merge(parsed)
        if len(merged) > self.settings.max_dependencies:
            raise ValueError(f"Dependency count exceeds the {self.settings.max_dependencies} limit")
        for dep in merged:
            dep.purl = package_url(dep.ecosystem, dep.name, dep.version)  # type: ignore[attr-defined]
            if not dep.pinned:
                result.warnings.append(f"Unpinned dependency: {dep.name} ({dep.ecosystem}) in {dep.source_file}")
        result.dependencies = sorted(merged, key=lambda d: (d.ecosystem, d.name.lower(), d.version))
        result.ecosystems = sorted({dep.ecosystem for dep in result.dependencies})
        result.project_type = self._project_type(result.ecosystems, result.dependency_files)
        result.dependency_files = sorted(set(result.dependency_files))
        result.warnings = _dedupe_strings(result.warnings)[:200]
        return result

    def _merge(self, dependencies: list[ParsedDependency]) -> list[ParsedDependency]:
        grouped: dict[tuple[str, str], list[ParsedDependency]] = {}
        for dep in dependencies:
            grouped.setdefault((dep.ecosystem, dep.name), []).append(dep)
        merged: list[ParsedDependency] = []
        for deps in grouped.values():
            pinned = [dep for dep in deps if dep.pinned and dep.version]
            unpinned = [dep for dep in deps if not (dep.pinned and dep.version)]
            direct_declared = any(dep.direct for dep in deps)
            if pinned:
                by_version: dict[str, ParsedDependency] = {}
                for dep in pinned:
                    existing = by_version.get(dep.version)
                    if existing:
                        existing.direct = existing.direct or dep.direct
                        existing.source_files = sorted(
                            set(getattr(existing, "source_files", []) + [dep.source_file]) - {""}
                        )
                        if dep.scope == "runtime" or existing.scope == "runtime":
                            existing.scope = "runtime"
                    else:
                        dep.source_files = [dep.source_file] if dep.source_file else []
                        if direct_declared and len(by_version) == 0:
                            dep.direct = dep.direct or any(d.direct for d in unpinned)
                        by_version[dep.version] = dep
                merged.extend(by_version.values())
            else:
                primary = unpinned[0]
                primary.direct = any(dep.direct for dep in unpinned)
                primary.source_files = sorted({dep.source_file for dep in unpinned if dep.source_file})
                merged.append(primary)
        for dep in merged:
            if not getattr(dep, "source_files", None):
                dep.source_files = [dep.source_file] if dep.source_file else []
        return merged

    @staticmethod
    def _project_type(ecosystems: list[str], files: list[str]) -> str:
        if len(ecosystems) > 1:
            return "multi-language"
        if ecosystems:
            return {
                "PyPI": "python",
                "npm": "javascript",
                "Maven": "java",
                "crates.io": "rust",
            }.get(ecosystems[0], ecosystems[0].lower())
        if files:
            return "dependency-files-only"
        return "unknown"


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output
