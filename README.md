# Dependency Watcher

Dependency Watcher is a self-hosted software composition analysis (SCA) tool. It
inventories the dependencies of a project, matches exact versions against
[OSV.dev](https://osv.dev), enriches findings with NVD CVSS data, evaluates
dependency health and remediation priority, and exports reports and CycloneDX
SBOMs. It ships with a FastAPI backend, a React dashboard and a CLI.

Everything runs locally: the only outbound traffic is to the vulnerability and
package-registry APIs you enable.

## Features

- **Project sources** — local directory, ZIP upload, or GitHub repository
  (public, or private with a token).
- **Ecosystems** — PyPI, npm, Maven and crates.io.
- **Dependency discovery** — direct and transitive dependencies from manifests
  and lock files, with pinned/unpinned detection and package URLs (purl).
- **Vulnerability detection** — exact-version matching through the OSV.dev
  batch API, advisory details, aliases (CVE/GHSA), CVSS scores and optional NVD
  enrichment. Dependencies without a fixed version are reported as `UNKNOWN`
  instead of `SAFE`.
- **Risk assessment** — severity, directness, exploitability signals, health
  and remediation effort combined into a proprietary priority score, plus a
  project-level Security Score with an A–F grade.
- **Dependency health** — latest versions, outdated and deprecated packages,
  licenses and unpinned dependencies from PyPI, npm, Maven Central and
  crates.io.
- **Remediation guidance** — recommended fixed versions, breaking-change risk
  and conflicting constraints.
- **CycloneDX SBOM** — JSON and XML, spec 1.5, with vulnerabilities.
- **Reports** — JSON, HTML, CSV and PDF, including an executive summary,
  unverified components, sources, warnings and limitations.
- **History and comparison** — every scan is stored; compare two scans to see
  added/removed/changed dependencies and new/resolved vulnerabilities.
- **CLI** — scan, list, show, report, SBOM, compare and serve commands with
  CI-friendly exit codes.
- **Hardened by default** — ZIP-slip protection, archive and upload limits,
  outbound-host allow-lists, XML hardening, rate limits, security headers and
  masked API keys.

## Architecture

```
frontend/ (React + Vite)  ──HTTP──▶  backend/ (FastAPI)
                                        │
             ┌──────────────────────────┼───────────────────────────┐
             ▼                          ▼                           ▼
        scanners/ + parsers/      vulnerability_engine/        services/
        (local/ZIP/GitHub)        (OSV.dev, NVD, cache)        (health, risk,
             │                          │                      remediation,
             ▼                          ▼                      comparison, reports)
        SQLite database  ◀──────── scan_service orchestration ────────▶ sbom/
```

See [docs/architecture.md](docs/architecture.md) for module details and the scan
lifecycle, and [docs/threat-model.md](docs/threat-model.md) for the security
model.

## Requirements

- Python 3.11+
- Node.js 20+ (for the frontend)
- SQLite (bundled with Python)

## Quick start

### 1. Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

The API is available at <http://127.0.0.1:8000/api/docs>. Data (database,
cache, settings, extracted archives) is stored in `../data` by default.

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open <http://127.0.0.1:5173>. Vite proxies `/api` to the backend.

To serve the built UI from the API instead:

```bash
cd frontend
npm run build
```

`backend/app/main.py` automatically mounts `frontend/dist` when it exists, so
<http://127.0.0.1:8000> serves the dashboard.

### 3. Try an example

```bash
python cli/dw.py scan examples/python-vulnerable --report json,html
```

## CLI

The CLI lives at `cli/dw.py` and uses the same data directory as the API.

```bash
# Scan a local project
python cli/dw.py scan /absolute/path/to/project --report json,html,csv,pdf --sbom json,xml

# Scan a GitHub repository (branch/tag optional)
python cli/dw.py scan https://github.com/owner/repo/tree/main --github

# Fail CI when high or critical findings exist (exit code 3)
python cli/dw.py scan . --fail-on high

# Work with existing scans
python cli/dw.py list
python cli/dw.py show <scan_id>
python cli/dw.py report <scan_id> --format pdf --output report.pdf
python cli/dw.py sbom <scan_id> --format xml --output sbom.cdx.xml
python cli/dw.py compare <scan_a> <scan_b>
python cli/dw.py serve --host 127.0.0.1 --port 8000
```

Useful flags: `--no-osv` (skip vulnerability checks), `--no-registry` (skip
latest-version/license lookups), `--no-github`, `--data-dir <path>`, `--json`.

Exit codes: `0` success, `1` scan failed, `2` invalid input/not found, `3`
`--fail-on` threshold exceeded.

## API overview

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/scans` | Queue a local or GitHub scan |
| `POST` | `/api/scans/upload` | Queue a ZIP-upload scan |
| `GET` | `/api/scans` | List scans (status filter, pagination) |
| `GET` | `/api/scans/{id}` | Scan detail |
| `DELETE` | `/api/scans/{id}` | Delete a scan and its findings |
| `GET` | `/api/scans/{id}/dependencies` | Filter/search dependencies |
| `GET` | `/api/scans/{id}/vulnerabilities` | Filter/search vulnerabilities |
| `GET` | `/api/scans/{id}/dependencies/{dep_id}` | Dependency detail |
| `GET` | `/api/scans/{id}/sbom?format=json\|xml` | CycloneDX SBOM |
| `GET` | `/api/scans/{id}/remediation` | Remediation plan |
| `GET` | `/api/scans/{id}/reports/{json\|html\|csv\|pdf}` | Report download |
| `GET` | `/api/compare?scan_a=…&scan_b=…` | Scan comparison |
| `GET` | `/api/health` | Health and enabled sources |
| `GET` | `/api/meta` | Ecosystems, supported files, limits |
| `GET`/`PUT` | `/api/settings` | Read/update non-secret settings |
| `DELETE` | `/api/settings/cache` | Clear the vulnerability/metadata cache |

## Supported dependency files

| Ecosystem | Files |
| --- | --- |
| PyPI | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock` |
| npm | `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Maven | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` |
| crates.io | `Cargo.toml`, `Cargo.lock` |

Manifests contribute direct dependencies; lock files contribute resolved
versions and transitive dependencies. When a dependency file cannot be parsed,
the scan records a warning instead of failing.

## Configuration

All settings are environment variables. Runtime-toggleable settings can also be
changed from the Settings page or `PUT /api/settings` and are persisted to
`data/settings.json` (mode `0600`); API keys are never returned by the API.

| Variable | Default | Description |
| --- | --- | --- |
| `DW_DATA_DIR` | `<repo>/data` | Database, cache, settings and work directory |
| `DW_DATABASE_URL` | `sqlite:///<data>/dependency_watcher.db` | SQLAlchemy URL |
| `DW_FRONTEND_DIST` | auto-detected | Path to a built frontend |
| `DW_HOST` / `DW_PORT` | `127.0.0.1` / `8000` | API bind address |
| `DW_RELOAD` | off | Uvicorn auto-reload |
| `DW_LOG_LEVEL` | `INFO` | Log level |
| `DW_ALLOW_LOCAL_PATHS` | `true` | Allow scanning local directories |
| `DW_ENABLE_OSV` | `true` | OSV.dev vulnerability source |
| `DW_ENABLE_REGISTRY` | `true` | Registry health lookups |
| `DW_ENABLE_NVD` | `false` | NVD CVSS enrichment |
| `DW_ENABLE_GITHUB` | `true` | GitHub repository source |
| `DW_NVD_API_KEY` | empty | NVD API key (higher rate limits) |
| `DW_GITHUB_TOKEN` | empty | GitHub token for private repositories |
| `DW_HTTP_TIMEOUT` | `20` | Outbound HTTP timeout (seconds) |
| `DW_MAX_UPLOAD_BYTES` | `52428800` | Max ZIP/GitHub archive size |
| `DW_MAX_ARCHIVE_FILES` | `10000` | Max files in an archive |
| `DW_MAX_EXTRACTED_BYTES` | `262144000` | Max total extracted bytes |
| `DW_MAX_PROJECT_FILES` | `50000` | Max files walked per project |
| `DW_MAX_DEPENDENCIES` | `20000` | Max parsed dependencies |
| `DW_MAX_DEPENDENCY_FILE_BYTES` | `20971520` | Max size of one dependency file |
| `DW_CACHE_TTL` | `21600` | Vulnerability/metadata cache TTL |
| `DW_RATE_LIMIT_PER_MINUTE` | `180` | API requests per minute per client |
| `DW_SCAN_RATE_LIMIT_PER_HOUR` | `60` | Scans per hour per client |

## Security Score

The project score is a 0–100 heuristic (not CVSS):

1. Any `CRITICAL` or `HIGH` finding sets the raw score to `0`.
2. Otherwise penalties are `medium×8 + low×3 + info×1`, plus outdated,
   deprecated and unpinned penalties.
3. The result is scaled by vulnerability coverage:
   `score = raw × (0.35 + 0.65 × coverage)`, then mapped to a letter grade.

Dependency and vulnerability priority scores are separate, documented
heuristics. Every report states this explicitly.

## Database migrations

Alembic lives in `backend/migrations`:

```bash
cd backend
alembic upgrade head          # apply migrations
alembic revision --autogenerate -m "describe change"
alembic check                 # verify models and migrations agree
```

The API also creates missing tables on startup for convenience; migrations
remain the source of truth for schema changes.

## Tests

```bash
# Backend
cd backend
pip install -r requirements-dev.txt
python -m pytest -q

# Frontend
cd frontend
npm test
npm run build
```

## Examples

`examples/` contains intentionally vulnerable projects for Python, Node.js,
Java and Rust. Each has its own README with a ready-to-run command.

## Limitations

- Vulnerability matching requires an exact resolved version; unpinned
  dependencies are reported as `UNKNOWN`.
- Transitive graphs are inferred only where lock files expose them.
- Coverage depends on OSV.dev and registry availability; failures are surfaced
  as warnings, errors and `UNKNOWN` states rather than silent success.
- Dependency Watcher is not a runtime protection tool and does not replace a
  full application security review.
- There is no built-in authentication; bind to localhost or place it behind an
  authenticating reverse proxy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
