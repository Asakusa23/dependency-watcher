from __future__ import annotations

from pathlib import Path

from app.core.config import AppSettings
from app.core.security import ExtractedProject, safe_extract_zip


class ArchiveExtractor:
    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings

    def extract(self, archive_path: Path, destination: Path) -> ExtractedProject:
        return safe_extract_zip(
            archive_path,
            destination,
            max_files=self.settings.max_archive_files,
            max_total_bytes=self.settings.max_extracted_bytes,
            max_file_bytes=self.settings.max_extracted_bytes,
        )
