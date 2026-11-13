from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from app.parsers.base import (
    ECOSYSTEM_CRATES,
    DependencyParser,
    ParserResult,
    ParsedDependency,
    relative_source,
)


def _parse_cargo_table(
    result: ParserResult, table: dict[str, Any], scope: str, source: str, direct: bool = True
) -> None:
    if not isinstance(table, dict):
        return
    for name, spec in table.items():
        if not isinstance(name, str):
            continue
        version = ""
        specifier = ""
        if isinstance(spec, dict) and spec.get("package"):
            name = str(spec["package"])
        if isinstance(spec, str):
            specifier = spec
        elif isinstance(spec, dict):
            specifier = str(spec.get("version", ""))
            if not specifier and (spec.get("git") or spec.get("path")):
                specifier = "unpinned"
        else:
            continue
        candidate = specifier.strip()
        if candidate.startswith("="):
            candidate = candidate.lstrip("=").strip()
            if candidate and candidate[0].isdigit():
                version = candidate
        elif candidate and candidate[0].isdigit():
            version = candidate
        result.add(
            ParsedDependency(
                name=name,
                ecosystem=ECOSYSTEM_CRATES,
                version=version,
                specifier=specifier,
                direct=direct,
                scope=scope,
                source_file=source,
                pinned=bool(version),
            )
        )


class CargoTomlParser(DependencyParser):
    name = "cargo-toml"
    filenames = {"Cargo.toml"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        _parse_cargo_table(result, data.get("dependencies", {}), "runtime", source)
        _parse_cargo_table(result, data.get("dev-dependencies", {}), "dev", source)
        _parse_cargo_table(result, data.get("build-dependencies", {}), "build", source)
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            _parse_cargo_table(result, workspace.get("dependencies", {}), "runtime", source)
        targets = data.get("target", {})
        if isinstance(targets, dict):
            for target in targets.values():
                if isinstance(target, dict):
                    _parse_cargo_table(result, target.get("dependencies", {}), "runtime", source)
                    _parse_cargo_table(result, target.get("dev-dependencies", {}), "dev", source)
        return result


class CargoLockParser(DependencyParser):
    name = "cargo-lock"
    filenames = {"Cargo.lock"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        direct_names = self._direct_names(path.parent / "Cargo.toml", result)
        for package in data.get("package", []) or []:
            if not isinstance(package, dict):
                continue
            name = str(package.get("name", ""))
            version = str(package.get("version", ""))
            registry_source = package.get("source")
            if not name or not version:
                continue
            if not registry_source:
                continue
            result.add(
                ParsedDependency(
                    name=name,
                    ecosystem=ECOSYSTEM_CRATES,
                    version=version,
                    direct=name in direct_names,
                    scope="runtime",
                    source_file=source,
                    pinned=True,
                )
            )
        return result

    @staticmethod
    def _direct_names(cargo_toml: Path, result: ParserResult) -> set[str]:
        if not cargo_toml.exists():
            return set()
        try:
            data = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse sibling Cargo.toml: {exc}")
            return set()
        names: set[str] = set()
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            names.update(str(key) for key in (data.get(section, {}) or {}))
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            names.update(str(key) for key in (workspace.get("dependencies", {}) or {}))
        return names
