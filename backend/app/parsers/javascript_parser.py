from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from app.core.versions import extract_pinned_version, is_pinned_version
from app.parsers.base import (
    ECOSYSTEM_NPM,
    DependencyParser,
    ParserResult,
    ParsedDependency,
    add_versioned,
    relative_source,
)


def _read_package_json(path: Path, result: ParserResult) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result.warnings.append(f"Could not parse {path.name}: {exc}")
        return {}


def _sibling_direct(path: Path, result: ParserResult) -> dict[str, str]:
    data = _read_package_json(path.parent / "package.json", result)
    direct: dict[str, str] = {}
    for section, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ):
        for name in (data.get(section, {}) or {}):
            direct.setdefault(str(name), scope)
    return direct


class PackageJsonParser(DependencyParser):
    name = "package-json"
    filenames = {"package.json"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        data = _read_package_json(path, result)
        for section, scope in (
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("optionalDependencies", "optional"),
            ("peerDependencies", "peer"),
        ):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                if not isinstance(spec, str):
                    continue
                version = extract_pinned_version(spec, ECOSYSTEM_NPM)
                result.add(
                    ParsedDependency(
                        name=str(name),
                        ecosystem=ECOSYSTEM_NPM,
                        version=version,
                        specifier=spec,
                        direct=True,
                        scope=scope,
                        source_file=source,
                        pinned=is_pinned_version(spec, ECOSYSTEM_NPM),
                    )
                )
        return result


class PackageLockParser(DependencyParser):
    name = "package-lock"
    filenames = {"package-lock.json"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        data = _read_package_json(path, result)
        if not data:
            return result
        packages = data.get("packages")
        if isinstance(packages, dict):
            root = packages.get("", {}) if isinstance(packages.get("", {}), dict) else {}
            direct_scopes: dict[str, str] = {}
            for section, scope in (
                ("dependencies", "runtime"),
                ("devDependencies", "dev"),
                ("optionalDependencies", "optional"),
                ("peerDependencies", "peer"),
            ):
                for name in (root.get(section, {}) or {}):
                    direct_scopes.setdefault(str(name), scope)
            for key, info in packages.items():
                if key == "" or not isinstance(info, dict) or info.get("link"):
                    continue
                name = info.get("name") or self._name_from_key(key)
                version = str(info.get("version", ""))
                if not name or not version:
                    continue
                top_level = key == f"node_modules/{name}"
                direct = top_level and name in direct_scopes
                scope = direct_scopes.get(name, "runtime") if direct else ("dev" if info.get("dev") else "runtime")
                if info.get("optional") and not direct:
                    scope = "optional"
                result.add(
                    ParsedDependency(
                        name=str(name),
                        ecosystem=ECOSYSTEM_NPM,
                        version=version,
                        direct=direct,
                        scope=scope,
                        source_file=source,
                        pinned=True,
                        license=str(info.get("license") or ""),
                    )
                )
            if result.dependencies:
                return result

        legacy = data.get("dependencies")
        if isinstance(legacy, dict):
            for name, info in legacy.items():
                self._walk_v1(result, str(name), info, source, direct=True, scope="runtime")
        return result

    @staticmethod
    def _name_from_key(key: str) -> str:
        parts = key.split("node_modules/")
        if len(parts) > 1:
            return parts[-1].strip("/")
        return key.strip("/")

    def _walk_v1(
        self,
        result: ParserResult,
        name: str,
        info: Any,
        source: str,
        *,
        direct: bool,
        scope: str,
        depth: int = 0,
    ) -> None:
        if not isinstance(info, dict) or depth > 20:
            return
        version = str(info.get("version", ""))
        if version:
            result.add(
                ParsedDependency(
                    name=name,
                    ecosystem=ECOSYSTEM_NPM,
                    version=version,
                    direct=direct,
                    scope="dev" if info.get("dev") else scope,
                    source_file=source,
                    pinned=True,
                    license=str(info.get("license") or ""),
                )
            )
        for child_name, child in (info.get("dependencies", {}) or {}).items():
            self._walk_v1(result, str(child_name), child, source, direct=False, scope=scope, depth=depth + 1)


class PnpmLockParser(DependencyParser):
    name = "pnpm-lock"
    filenames = {"pnpm-lock.yaml"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            yaml = YAML(typ="safe", pure=True)
            data = yaml.load(path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        direct_scopes = _sibling_direct(path, result)
        importers = data.get("importers", {}) if isinstance(data, dict) else {}
        root_importer = importers.get(".", {}) if isinstance(importers, dict) else {}
        for section, scope in (
            ("dependencies", "runtime"),
            ("devDependencies", "dev"),
            ("optionalDependencies", "optional"),
        ):
            entries = root_importer.get(section, {}) if isinstance(root_importer, dict) else {}
            if not isinstance(entries, dict):
                continue
            for name, info in entries.items():
                version = self._importer_version(info)
                if version:
                    result.add(
                        ParsedDependency(
                            name=str(name),
                            ecosystem=ECOSYSTEM_NPM,
                            version=version,
                            direct=True,
                            scope=scope,
                            source_file=source,
                            pinned=True,
                        )
                    )
                    direct_scopes.setdefault(str(name), scope)
        packages = data.get("packages", {}) if isinstance(data, dict) else {}
        for section in ("packages", "snapshots"):
            entries = data.get(section, {}) if isinstance(data, dict) else {}
            if not isinstance(entries, dict):
                continue
            for key, info in entries.items():
                parsed = self._split_key(str(key))
                if not parsed:
                    continue
                name, version = parsed
                direct = name in direct_scopes
                scope = direct_scopes.get(name, "runtime") if direct else "runtime"
                license = ""
                if isinstance(info, dict):
                    license = str(info.get("license") or "")
                result.add(
                    ParsedDependency(
                        name=name,
                        ecosystem=ECOSYSTEM_NPM,
                        version=version,
                        direct=direct,
                        scope=scope,
                        source_file=source,
                        pinned=True,
                        license=license,
                    )
                )
        result.dependencies = _dedupe(result.dependencies)
        return result

    @staticmethod
    def _importer_version(info: Any) -> str:
        if isinstance(info, str):
            version = info
        elif isinstance(info, dict):
            version = str(info.get("version", ""))
        else:
            return ""
        version = version.split("(", 1)[0]
        return version.lstrip("v")

    @staticmethod
    def _split_key(key: str) -> tuple[str, str] | None:
        key = key.strip().strip("\"'")
        if not key or key.startswith("__") or key in {".", "/"}:
            return None
        if key.startswith("/"):
            key = key[1:]
        if "@" in key[1:]:
            name, version = key.rsplit("@", 1)
            version = version.split("(", 1)[0]
            if name and version:
                return name, version
        parts = key.rsplit("/", 1)
        if len(parts) == 2 and re.match(r"^\d", parts[1]):
            return parts[0], parts[1].split("(", 1)[0]
        return None


class YarnLockParser(DependencyParser):
    name = "yarn-lock"
    filenames = {"yarn.lock"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        direct_scopes = _sibling_direct(path, result)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            result.warnings.append(f"Could not read {source}: {exc}")
            return result
        blocks: list[tuple[str, list[str]]] = []
        current_header: str | None = None
        current_lines: list[str] = []
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                if current_header is not None:
                    blocks.append((current_header, current_lines))
                current_header = line.strip()
                current_lines = []
            elif current_header is not None:
                current_lines.append(line)
        if current_header is not None:
            blocks.append((current_header, current_lines))

        for header, block in blocks:
            if header.startswith("__metadata"):
                continue
            name = self._descriptor_name(header)
            if not name:
                continue
            version = ""
            for line in block:
                match = re.match(r'^\s+version[:\s]+"?([^"\s]+)"?', line)
                if match:
                    version = match.group(1).strip()
                    break
            if not version:
                continue
            direct = name in direct_scopes
            result.add(
                ParsedDependency(
                    name=name,
                    ecosystem=ECOSYSTEM_NPM,
                    version=version,
                    direct=direct,
                    scope=direct_scopes.get(name, "runtime") if direct else "runtime",
                    source_file=source,
                    pinned=True,
                )
            )
        result.dependencies = _dedupe(result.dependencies)
        return result

    @staticmethod
    def _descriptor_name(header: str) -> str:
        cleaned = header.strip().strip('"').rstrip(":").strip()
        first = cleaned.split(",", 1)[0].strip().strip('"')
        first = first.split(":", 1)[0] if first.startswith(("npm:", "patch:")) else first
        match = re.match(r"^(@[^/@]+/[^@]+|[^@]+)@", first)
        if match:
            return match.group(1)
        return first if first and not first.startswith("__") else ""


def _dedupe(dependencies: list[ParsedDependency]) -> list[ParsedDependency]:
    merged: dict[tuple[str, str, str], ParsedDependency] = {}
    for dep in dependencies:
        key = (dep.ecosystem, dep.name, dep.version)
        if key in merged:
            existing = merged[key]
            existing.direct = existing.direct or dep.direct
            if dep.scope == "runtime":
                existing.scope = "runtime"
        else:
            merged[key] = dep
    return list(merged.values())
