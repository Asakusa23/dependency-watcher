from __future__ import annotations

import json
from pathlib import Path

from app.core.config import AppSettings
from app.scanners.scanner import ProjectScanner


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_scanner_detects_all_supported_ecosystems(settings: AppSettings, tmp_path: Path) -> None:
    project = tmp_path / "multi"
    write(project / "requirements.txt", "requests==2.25.1\nurllib3>=2.0\n")
    write(
        project / "package.json",
        json.dumps(
            {
                "dependencies": {"lodash": "4.17.20"},
                "devDependencies": {"typescript": "^5.0.0"},
            }
        ),
    )
    write(
        project / "pom.xml",
        """<project>
  <properties><spring.version>5.3.0</spring.version></properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>${spring.version}</version>
    </dependency>
  </dependencies>
</project>""",
    )
    write(
        project / "Cargo.toml",
        """[dependencies]
serde = "=1.0.100"
actix = { package = "actix-web", version = "4.0.0" }
""",
    )

    result = ProjectScanner(settings).scan(project)
    dependencies = {(dep.ecosystem, dep.name): dep for dep in result.dependencies}

    assert ("PyPI", "requests") in dependencies
    assert dependencies[("PyPI", "requests")].version == "2.25.1"
    assert dependencies[("PyPI", "requests")].pinned is True
    assert dependencies[("PyPI", "urllib3")].pinned is False
    assert dependencies[("PyPI", "urllib3")].version == ""
    assert dependencies[("npm", "lodash")].pinned is True
    assert dependencies[("npm", "typescript")].pinned is False
    assert dependencies[("Maven", "org.springframework:spring-core")].version == "5.3.0"
    assert dependencies[("crates.io", "serde")].version == "1.0.100"
    assert dependencies[("crates.io", "actix-web")].version == "4.0.0"
    assert result.project_type == "multi-language"
    assert result.ecosystems == ["Maven", "PyPI", "crates.io", "npm"]
    assert any("Unpinned dependency: urllib3" in warning for warning in result.warnings)


def test_scanner_ignores_vendor_directories_and_symlinks(settings: AppSettings, tmp_path: Path) -> None:
    project = tmp_path / "project"
    write(project / "requirements.txt", "requests==2.25.1\n")
    write(project / "node_modules" / "ignored" / "package.json", '{"dependencies":{"bad":"1.0.0"}}')
    outside = tmp_path / "outside.txt"
    outside.write_text("django==3.0.0\n", encoding="utf-8")
    try:
        (project / "linked.txt").symlink_to(outside)
    except OSError:
        pass

    result = ProjectScanner(settings).scan(project)
    assert [dep.name for dep in result.dependencies] == ["requests"]


def test_scanner_merges_duplicate_pinned_versions(settings: AppSettings, tmp_path: Path) -> None:
    project = tmp_path / "project"
    write(project / "requirements.txt", "requests==2.25.1\n")
    write(project / "requirements-dev.txt", "requests==2.25.1\n")
    result = ProjectScanner(settings).scan(project)
    requests = [dep for dep in result.dependencies if dep.name == "requests"]
    assert len(requests) == 1
    assert set(requests[0].source_files) == {"requirements.txt", "requirements-dev.txt"}
