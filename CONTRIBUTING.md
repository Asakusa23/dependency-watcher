# Contributing to Dependency Watcher

Thanks for helping improve Dependency Watcher. This project is a local SCA tool;
changes should preserve its security posture and its honest reporting of
unknown/error states.

## Development setup

```bash
# Backend
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements-dev.txt
alembic upgrade head
python -m pytest -q

# Frontend
cd ../frontend
npm install
npm test
npm run build
```

Run the API with `uvicorn app.main:app --reload --port 8000` and the UI with
`npm run dev` (Vite proxies `/api` to the backend).

## Project layout

- `backend/app/api` — routes, schemas, middleware.
- `backend/app/parsers` — one parser per ecosystem/file type.
- `backend/app/vulnerability_engine` — OSV/NVD clients, cache, CVSS.
- `backend/app/services` — orchestration, health, remediation, comparison.
- `backend/app/risk_engine` — priority and Security Score heuristics.
- `backend/app/reporting` and `backend/app/sbom` — output formats.
- `backend/migrations` — Alembic revisions.
- `frontend/src` — pages, components, hooks, API client.
- `cli/dw.py` — CLI entry point.

See `docs/architecture.md` for the scan lifecycle and extension points.

## Coding guidelines

- Python: 3.11+, type hints where practical, no comments unless they explain
  non-obvious intent. Keep network and parsing code defensive.
- TypeScript/React: functional components, existing UI primitives and Tailwind
  tokens, typed API responses in `src/types.ts`.
- Never execute project code or build scripts.
- Never weaken security limits, allow-lists, escaping or redaction.
- Treat tests as contracts: fix behavior in the implementation, not by loosening
  assertions, unless the test itself is demonstrably wrong.

## Adding an ecosystem

1. Implement a `DependencyParser` in `backend/app/parsers/`.
2. Register it in `parsers/registry.py` and expose supported filenames.
3. Add registry metadata support in `services/health_service.py`.
4. Add parser tests with realistic manifests and lock files.
5. Update `README.md` and `docs/architecture.md`.

## Adding a report format or API field

1. Extend `ReportService.context()` so all formats stay consistent.
2. Add the format to `ReportService`, `routes_reports.py`, the CLI and the UI.
3. Cover it with backend tests; update the API table in `README.md`.

## Database changes

- Update `models/db_models.py`.
- Generate a migration: `alembic revision --autogenerate -m "..."`.
- Review the generated revision (imports, defaults, indexes) and test
  `alembic upgrade head` and `alembic downgrade -1`.
- Run `alembic check` to confirm models and migrations agree.

## Tests

- Backend: `python -m pytest -q` (parser, risk, security, API, report tests).
- Frontend: `npm test` (Vitest + Testing Library).
- Add a regression test for every bug fix.

## Pull requests

- Keep changes focused and describe the motivation and behavior change.
- Include test evidence (commands and results).
- Update documentation and `CHANGELOG.md` for user-visible changes.
- Do not commit secrets, generated databases, `node_modules`, `dist` or scan
  artifacts.
- By contributing you agree that your changes are licensed under the MIT
  license.
