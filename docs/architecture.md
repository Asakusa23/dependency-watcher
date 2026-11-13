# Architecture

Dependency Watcher is a local, single-user SCA application composed of three
deliverables that share one data directory:

- `backend/` — FastAPI service, scan pipeline, persistence and reporting.
- `frontend/` — React + Vite dashboard.
- `cli/dw.py` — command-line client built on the same backend services.

## High-level view

```
┌──────────────────────┐        ┌───────────────────────────┐
│ React dashboard      │  HTTP  │ FastAPI (app.main)        │
│ Vite dev proxy /     │───────▶│ /api/scans, /api/reports, │
│ static dist          │        │ /api/compare, /api/settings│
└──────────────────────┘        └─────────────┬─────────────┘
                                              │
                                    app.api.deps / container
                                              │
                    ┌─────────────────────────┼──────────────────────────┐
                    ▼                         ▼                          ▼
            ScanService.execute        VulnerabilityEngine        ReportService
                    │                         │                    SbomGenerator
        ┌───────────┼───────────┐       ┌─────┴─────┐             RemediationService
        ▼           ▼           ▼       ▼           ▼             ComparisonService
   scanners/    parsers/   persistence  OSV.dev   NVD (optional)  health_service
   local ZIP    ecosystem  SQLAlchemy   client    enrichment      registry clients
   GitHub       parsers    SQLite
```

## Module map

| Path | Responsibility |
| --- | --- |
| `backend/app/main.py` | App factory, middleware, routers, SPA/static mounting |
| `backend/app/core/config.py` | `AppSettings`, environment parsing, paths and limits |
| `backend/app/core/container.py` | Composition root wiring services and clients |
| `backend/app/core/security.py` | URL validation, ZIP extraction, path containment |
| `backend/app/core/rate_limit.py` | In-memory request and scan limiters |
| `backend/app/api/` | Routes, request schemas, middleware, dependencies |
| `backend/app/scanners/` | Source acquisition: local, ZIP (`archive.py`), GitHub |
| `backend/app/parsers/` | Per-ecosystem manifest and lock-file parsers |
| `backend/app/vulnerability_engine/` | OSV batch/detail clients, NVD enrichment, CVSS, cache |
| `backend/app/services/health_service.py` | Registry metadata, latest versions, licenses, deprecations |
| `backend/app/risk_engine/` | Priority heuristics, severity ordering, Security Score |
| `backend/app/services/remediation_service.py` | Recommended upgrades, breaking risk, conflicts |
| `backend/app/sbom/` | CycloneDX 1.5 JSON/XML generation and purl helpers |
| `backend/app/reporting/` | JSON, HTML, CSV and PDF reports |
| `backend/app/services/scan_service.py` | Scan lifecycle orchestration and persistence |
| `backend/app/services/comparison_service.py` | Scan-to-scan diff of dependencies and findings |
| `backend/app/services/serializers.py` | API/report DTO shaping |
| `backend/app/models/db_models.py` | SQLAlchemy models: `Scan`, `Dependency`, `Vulnerability` |
| `backend/migrations/` | Alembic environment and revisions |
| `cli/dw.py` | CLI commands and CI exit codes |

## Scan lifecycle

1. **Create** — a `Scan` row is created (`pending`, `queued`) and a background
   task is scheduled. Uploads are extracted before queueing.
2. **Acquire source** (`acquiring_source`, 5%) — local path validation, reuse of
   the extracted upload, or a GitHub archive download through `codeload`.
3. **Discover dependencies** (`discovering_dependencies`, 15%) — the project is
   walked with size/file limits; each supported file is handled by exactly one
   parser. Results are deduplicated by `(ecosystem, name, version)`.
4. **Persist inventory** (`inspecting_dependencies`, 35%) — dependency rows are
   stored with direct/transitive flags, scope, purl, source files and
   pinned status.
5. **Query sources** (`querying_vulnerability_sources`, 50%) — OSV batch
   queries and registry health lookups run concurrently (bounded by
   semaphores).
6. **Assess risk** (`assessing_risk`, 80%) — advisories are persisted,
   per-vulnerability and per-dependency priorities are computed, counts and
   coverage are aggregated, and the project Security Score is calculated.
7. **Complete** (`completed`, 100%) — timestamps, duration, warnings, sources
   and SBOM serial are stored. Temporary work directories are removed in a
   `finally` block.

Failures are recorded on the scan (`failed`, `error_message`) and sanitized
before storage. A single dependency-file parse error becomes a warning; source
or database failures fail the scan.

## Data model

- `scans` — lifecycle/status, counts, Security Score and breakdown, coverage,
  warnings/errors, sources, metadata, SBOM serial.
- `dependencies` — one row per `(scan, ecosystem, name, version)`, with
  version specifier, purl, direct/transitive, scope, license, latest version,
  health, inspection status/message, priority, risk flags/reasons.
- `vulnerabilities` — one row per `(scan, dependency, osv_id)`, with aliases,
  CVE/GHSA IDs, CVSS, fixed/affected ranges, references, source and priority.

Cascades delete dependencies and findings with their scan. SQLite foreign keys
and WAL are enabled per connection.

## Vulnerability matching

- Dependencies without an exact version are never treated as safe; they are
  `UNKNOWN` with an explanatory message.
- OSV queries are batched (200 per request) with pagination support and
  per-query caching.
- Advisory details are fetched with bounded concurrency and cached.
- Withdrawn advisories are excluded from findings.
- Missing detail pages mark the dependency `ERROR` rather than silently
  dropping findings.
- If OSV is unavailable, affected dependencies become `ERROR` and the scan
  continues with a warning; if OSV is disabled, they become `UNKNOWN`.

## Scoring

- **Vulnerability priority** combines severity/CVSS, directness, exploitability
  signals and fix availability.
- **Dependency priority** aggregates vulnerability priorities with health
  signals (outdated, deprecated, unpinned).
- **Security Score** is a project-level heuristic: any `CRITICAL`/`HIGH` sets
  the raw score to zero; otherwise weighted penalties are applied and the score
  is scaled by coverage. It is explicitly not a CVSS score.

## Reporting and SBOM

Reports render from a single `ReportService.context()` document, so JSON, HTML,
CSV and PDF stay consistent. HTML escapes all values, restricts links to
HTTP(S) and ships a restrictive CSP. PDFs are generated with ReportLab. SBOMs
are CycloneDX 1.5 with components, dependency refs, vulnerabilities, ratings
and `dw:*` properties.

## Frontend

- `src/pages/` — Dashboard, Scans, Scan detail, Dependencies, Compare, Settings.
- `src/components/` — layout shell, tables, dialogs, charts, explorers and UI
  primitives (Radix + Tailwind).
- `src/context/ScanContext.tsx` — selected scan state shared across pages.
- `src/lib/api.ts` — typed API client; `src/lib/format.ts` — presentation
  helpers; `src/hooks/` — data fetching, polling and debouncing.

The UI is a single-page app; when `frontend/dist` exists the API serves it and
falls back to `index.html` for client-side routes, while refusing to shadow
`/api` and `/health`.

## Extension points

- **New ecosystem**: add a `DependencyParser` subclass, register it in
  `parsers/registry.py`, add registry lookup support in `health_service.py`,
  and cover it with parser and API tests.
- **New vulnerability source**: implement a client with caching and bounded
  retries, then integrate it in `vulnerability_engine/engine.py` and expose its
  state in `/api/health` and settings.
- **New report format**: add a method on `ReportService`, a route branch and a
  CLI/UI entry.
