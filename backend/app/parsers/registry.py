from __future__ import annotations

from pathlib import Path

from app.parsers.base import DependencyParser
from app.parsers.java_parser import GradleLockfileParser, GradleParser, PomParser
from app.parsers.javascript_parser import PackageJsonParser, PackageLockParser, PnpmLockParser, YarnLockParser
from app.parsers.python_parser import PipfileLockParser, PoetryLockParser, PyProjectParser, RequirementsParser
from app.parsers.rust_parser import CargoLockParser, CargoTomlParser


class ParserRegistry:
    """Maps dependency filenames to isolated ecosystem parsers."""

    def __init__(self, parsers: list[DependencyParser] | None = None) -> None:
        self.parsers: list[DependencyParser] = parsers or [
            RequirementsParser(),
            PyProjectParser(),
            PoetryLockParser(),
            PipfileLockParser(),
            PackageJsonParser(),
            PackageLockParser(),
            PnpmLockParser(),
            YarnLockParser(),
            PomParser(),
            GradleParser(),
            GradleLockfileParser(),
            CargoTomlParser(),
            CargoLockParser(),
        ]

    def detect(self, path: Path) -> DependencyParser | None:
        for parser in self.parsers:
            can_parse = getattr(parser, "can_parse", None)
            if callable(can_parse):
                if can_parse(path.name):
                    return parser
            elif path.name in parser.filenames:
                return parser
        return None

    @property
    def supported_filenames(self) -> set[str]:
        names: set[str] = set()
        for parser in self.parsers:
            names.update(parser.filenames)
        names.add("requirements.txt")
        return names
