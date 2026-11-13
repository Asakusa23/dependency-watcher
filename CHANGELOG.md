# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-13

### Added

- FastAPI backend with local, ZIP-upload and GitHub project sources.
- Dependency discovery for PyPI, npm, Maven and crates.io manifests and lock
  files, including transitive dependencies and pinned/unpinned detection.
- OSV.dev batch vulnerability matching with advisory details, CVE/GHSA aliases,
  CVSS parsing, pagination, caching and optional NVD enrichment.
- Registry health checks for latest versions, outdated/deprecated packages and
  licenses.
- Risk engine with vulnerability/dependency priority heuristics and a
  project-level Security Score with coverage scaling.
- Remediation recommendations with recommended fixed versions, breaking-change
  risk and conflicting constraints.
- CycloneDX 1.5 SBOM export (JSON and XML).
- JSON, HTML, CSV and PDF reports with executive summary, unverified components,
  sources, warnings and limitations.
- Scan history, filtering, dependency/vulnerability explorers and scan
  comparison (added/removed/changed dependencies, new/resolved findings).
- React dashboard with dashboard, scans, scan detail, dependencies, compare and
  settings pages.
- CLI with `scan`, `list`, `show`, `report`, `sbom`, `compare` and `serve`
  commands, plus `--fail-on` CI exit codes.
- Alembic migrations and an initial schema revision.
- Hardening: ZIP-slip and symlink rejection, archive/upload limits, SSRF
  allow-lists with public-address validation, defused XML parsing, report
  escaping and CSP, secret redaction, rate limits and security headers.
- Backend and frontend test suites, example vulnerable projects and
  documentation (`docs/architecture.md`, `docs/threat-model.md`).

### Fixed

- Remediation responses now expose `total`, `items` and per-item
  `fixed_version` consistently.
- Security Score now applies the documented policy: any `CRITICAL`/`HIGH`
  finding zeroes the score, and the breakdown records the severity policy.
- GitHub URLs with URL-encoded or traversal path segments are rejected, and
  single-root archives are unwrapped safely.
- The frontend `pluralize` helper now handles consonant + `y` correctly.
