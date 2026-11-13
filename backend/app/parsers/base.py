from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from app.core.versions import extract_pinned_version, is_pinned_version


ECOSYSTEM_PYPI = "PyPI"
ECOSYSTEM_NPM = "npm"
ECOSYSTEM_MAVEN = "Maven"
ECOSYSTEM_CRATES = "crates.io"


@dataclass
class ParsedDependency:
    name: str
    ecosystem: str
    version: str = ""
    specifier: str = ""
    direct: bool = True
    scope: str = "runtime"
    source_file: str = ""
    pinned: bool = False
    license: str = ""
    purl: str = ""
    source_files: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.pinned:
            self.pinned = is_pinned_version(self.version or self.specifier, self.ecosystem)
        if not self.version and self.pinned:
            self.version = extract_pinned_version(self.specifier, self.ecosystem)


@dataclass
class ParserResult:
    dependencies: list[ParsedDependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    parser: str = ""

    def add(self, dependency: ParsedDependency) -> None:
        if dependency.name:
            self.dependencies.append(dependency)


class DependencyParser(Protocol):
    name: str
    filenames: set[str]

    def parse(self, path: Path, project_root: Path) -> ParserResult: ...


def relative_source(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.name


def canonical_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip()).lower()


def add_versioned(
    result: ParserResult,
    *,
    name: str,
    ecosystem: str,
    spec: str,
    direct: bool,
    scope: str,
    source_file: str,
    version: str = "",
    pinned: bool | None = None,
    license: str = "",
) -> None:
    if not name:
        return
    version_value = version or extract_pinned_version(spec, ecosystem)
    if pinned is None:
        pinned = is_pinned_version(version_value or spec, ecosystem)
    result.add(
        ParsedDependency(
            name=name,
            ecosystem=ecosystem,
            version=version_value,
            specifier=spec,
            direct=direct,
            scope=scope,
            source_file=source_file,
            pinned=pinned,
            license=license,
        )
    )
