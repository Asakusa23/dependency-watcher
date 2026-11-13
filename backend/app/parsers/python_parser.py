from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from app.core.versions import extract_pinned_version, is_pinned_version
from app.parsers.base import (
    ECOSYSTEM_PYPI,
    DependencyParser,
    ParserResult,
    ParsedDependency,
    add_versioned,
    canonical_pypi_name,
    relative_source,
)


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    line = re.split(r"\s+--hash[=\s]", line, maxsplit=1)[0].strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("-"):
        return None
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    try:
        from packaging.requirements import Requirement

        req = Requirement(line)
        name = canonical_pypi_name(req.name)
        spec = str(req.specifier)
        if req.url and not spec:
            spec = req.url
        return name, spec
    except Exception:
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*([<>=!~].*)?$", line)
        if not match:
            return None
        return canonical_pypi_name(match.group(1)), (match.group(2) or "").strip()


class RequirementsParser(DependencyParser):
    name = "requirements"
    filenames = {"requirements.txt"}

    def can_parse(self, filename: str) -> bool:
        return bool(re.match(r"^requirements([._-].*)?\.txt$", filename, re.IGNORECASE))

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            result.warnings.append(f"Could not read {source}: {exc}")
            return result
        text = re.sub(r"\\\s*\n", " ", text)
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.startswith(("-r ", "--requirement", "-c ", "--constraint", "-e ", "--editable")):
                result.warnings.append(f"Included/editable requirement not expanded in {source}: {stripped[:100]}")
                continue
            parsed = _parse_requirement_line(stripped)
            if not parsed:
                continue
            name, spec = parsed
            add_versioned(
                result,
                name=name,
                ecosystem=ECOSYSTEM_PYPI,
                spec=spec,
                direct=True,
                scope="runtime",
                source_file=source,
            )
        return result


class PyProjectParser(DependencyParser):
    name = "pyproject"
    filenames = {"pyproject.toml"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result

        project = data.get("project", {})
        for dep in project.get("dependencies", []) or []:
            if not isinstance(dep, str):
                continue
            parsed = _parse_requirement_line(dep)
            if parsed:
                add_versioned(
                    result,
                    name=parsed[0],
                    ecosystem=ECOSYSTEM_PYPI,
                    spec=parsed[1],
                    direct=True,
                    scope="runtime",
                    source_file=source,
                )
        for group, deps in (project.get("optional-dependencies", {}) or {}).items():
            for dep in deps or []:
                parsed = _parse_requirement_line(str(dep))
                if parsed:
                    add_versioned(
                        result,
                        name=parsed[0],
                        ecosystem=ECOSYSTEM_PYPI,
                        spec=parsed[1],
                        direct=True,
                        scope=f"optional:{group}",
                        source_file=source,
                    )

        poetry = data.get("tool", {}).get("poetry", {})
        if poetry:
            self._add_poetry_table(result, poetry.get("dependencies", {}), "runtime", source)
            self._add_poetry_table(result, poetry.get("dev-dependencies", {}), "dev", source)
            for group_name, group in (poetry.get("group", {}) or {}).items():
                if isinstance(group, dict):
                    self._add_poetry_table(result, group.get("dependencies", {}), group_name, source)
        return result

    @staticmethod
    def _add_poetry_table(result: ParserResult, table: dict, scope: str, source: str) -> None:
        if not isinstance(table, dict):
            return
        for raw_name, raw_spec in table.items():
            name = canonical_pypi_name(str(raw_name))
            if name == "python":
                continue
            if isinstance(raw_spec, str):
                spec = raw_spec
                optional = False
            elif isinstance(raw_spec, dict):
                spec = str(raw_spec.get("version", ""))
                optional = bool(raw_spec.get("optional", False))
                if raw_spec.get("git") or raw_spec.get("path") or raw_spec.get("url"):
                    spec = spec or "unpinned"
            else:
                spec = ""
            version = extract_pinned_version(spec, ECOSYSTEM_PYPI)
            result.add(
                ParsedDependency(
                    name=name,
                    ecosystem=ECOSYSTEM_PYPI,
                    version=version,
                    specifier=spec,
                    direct=True,
                    scope=("optional" if optional and scope == "runtime" else scope),
                    source_file=source,
                    pinned=is_pinned_version(version or spec, ECOSYSTEM_PYPI),
                )
            )


class PoetryLockParser(DependencyParser):
    name = "poetry-lock"
    filenames = {"poetry.lock"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        for package in data.get("package", []) or []:
            if not isinstance(package, dict):
                continue
            name = canonical_pypi_name(str(package.get("name", "")))
            version = str(package.get("version", ""))
            if not name or not version:
                continue
            category = str(package.get("category", "main"))
            scope = "dev" if category in {"dev", "develop"} else "runtime"
            result.add(
                ParsedDependency(
                    name=name,
                    ecosystem=ECOSYSTEM_PYPI,
                    version=version,
                    specifier="",
                    direct=False,
                    scope=scope,
                    source_file=source,
                    pinned=True,
                )
            )
        return result


class PipfileLockParser(DependencyParser):
    name = "pipfile-lock"
    filenames = {"Pipfile.lock"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        direct_names = self._direct_names(path.parent / "Pipfile", result)
        for section, scope in (("default", "runtime"), ("develop", "dev")):
            for name, info in (data.get(section, {}) or {}).items():
                normalized = canonical_pypi_name(str(name))
                version_spec = str((info or {}).get("version", "")) if isinstance(info, dict) else ""
                version = extract_pinned_version(version_spec, ECOSYSTEM_PYPI)
                result.add(
                    ParsedDependency(
                        name=normalized,
                        ecosystem=ECOSYSTEM_PYPI,
                        version=version,
                        specifier=version_spec,
                        direct=normalized in direct_names,
                        scope=scope,
                        source_file=source,
                        pinned=bool(version),
                    )
                )
        if not direct_names:
            result.warnings.append("Pipfile.lock has no sibling Pipfile; direct/transitive status is unknown")
        return result

    @staticmethod
    def _direct_names(pipfile: Path, result: ParserResult) -> set[str]:
        if not pipfile.exists():
            return set()
        try:
            data = tomllib.loads(pipfile.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            result.warnings.append(f"Could not parse sibling Pipfile: {exc}")
            return set()
        names: set[str] = set()
        for section in ("packages", "dev-packages"):
            for name in (data.get(section, {}) or {}):
                names.add(canonical_pypi_name(str(name)))
        return names
