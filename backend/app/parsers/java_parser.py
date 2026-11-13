from __future__ import annotations

import re
from pathlib import Path

from defusedxml import ElementTree as DefusedET

from app.parsers.base import (
    ECOSYSTEM_MAVEN,
    DependencyParser,
    ParserResult,
    ParsedDependency,
    add_versioned,
    relative_source,
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(node, name: str) -> str:  # noqa: ANN001
    for child in list(node):
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


class PomParser(DependencyParser):
    name = "pom"
    filenames = {"pom.xml"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            root = DefusedET.parse(path).getroot()
        except Exception as exc:
            result.warnings.append(f"Could not parse {source}: {exc}")
            return result
        properties: dict[str, str] = {}
        for child in list(root):
            if _local(child.tag) == "properties":
                for prop in list(child):
                    properties[_local(prop.tag)] = (prop.text or "").strip()
        for field in ("groupId", "artifactId", "version"):
            value = _child_text(root, field)
            if value:
                properties[f"project.{field}"] = value
        for field in ("groupId", "artifactId", "version"):
            properties.setdefault(field, properties.get(f"project.{field}", ""))

        dependencies_node = None
        for child in list(root):
            if _local(child.tag) == "dependencies":
                dependencies_node = child
                break
        if dependencies_node is None:
            return result

        for dep in list(dependencies_node):
            if _local(dep.tag) != "dependency":
                continue
            group = self._resolve(_child_text(dep, "groupId"), properties)
            artifact = self._resolve(_child_text(dep, "artifactId"), properties)
            version = self._resolve(_child_text(dep, "version"), properties)
            scope = _child_text(dep, "scope") or "compile"
            optional = _child_text(dep, "optional").lower() == "true"
            if not group or not artifact:
                result.warnings.append(f"Skipped malformed Maven dependency in {source}")
                continue
            if "${" in version:
                version = ""
            add_versioned(
                result,
                name=f"{group}:{artifact}",
                ecosystem=ECOSYSTEM_MAVEN,
                spec=version,
                direct=True,
                scope=("optional" if optional else ("dev" if scope in {"test", "provided"} else "runtime")),
                source_file=source,
                version=version,
                pinned=bool(version),
            )
        return result

    @staticmethod
    def _resolve(value: str, properties: dict[str, str]) -> str:
        if not value:
            return value
        return re.sub(
            r"\$\{([^}]+)\}",
            lambda match: properties.get(match.group(1), match.group(0)),
            value,
        )


_GRADLE_RE = re.compile(
    r"""(?P<config>\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt|compile))\s*[\(\s]\s*['"](?P<coord>[^'"]+)['"]"""
)


class GradleParser(DependencyParser):
    name = "gradle"
    filenames = {"build.gradle", "build.gradle.kts"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.warnings.append(f"Could not read {source}: {exc}")
            return result
        for match in _GRADLE_RE.finditer(text):
            coord = match.group("coord").strip()
            parts = coord.split(":")
            if len(parts) < 2:
                continue
            group, artifact = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else ""
            if version.startswith(("$", "@")):
                version = ""
            config = match.group("config")
            add_versioned(
                result,
                name=f"{group}:{artifact}",
                ecosystem=ECOSYSTEM_MAVEN,
                spec=version,
                direct=True,
                scope="dev" if config.startswith("test") else ("compileOnly" if config in {"compileOnly", "annotationProcessor", "kapt"} else "runtime"),
                source_file=source,
                version=version,
                pinned=bool(version),
            )
        if not result.dependencies:
            result.warnings.append(f"No literal Maven coordinates extracted from {source}; variable-based declarations may be missed")
        return result


class GradleLockfileParser(DependencyParser):
    name = "gradle-lockfile"
    filenames = {"gradle.lockfile"}

    def parse(self, path: Path, project_root: Path) -> ParserResult:
        result = ParserResult(parser=self.name)
        source = relative_source(path, project_root)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            result.warnings.append(f"Could not read {source}: {exc}")
            return result
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coord = line.split("=", 1)[0].strip()
            parts = coord.split(":")
            if len(parts) < 3:
                continue
            group, artifact, version = parts[0], parts[1], parts[2]
            result.add(
                ParsedDependency(
                    name=f"{group}:{artifact}",
                    ecosystem=ECOSYSTEM_MAVEN,
                    version=version,
                    direct=False,
                    scope="runtime",
                    source_file=source,
                    pinned=True,
                )
            )
        return result
