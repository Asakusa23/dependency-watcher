# Roadmap

This roadmap is directional, not a commitment. Priorities favor correctness,
honest coverage reporting and a small, auditable codebase.

## Near term

- Expand frontend component tests (scan creation, tables, dialogs, error and
  empty states) and add accessibility checks.
- Add OSV `querybatch` result caching tests and contract tests with recorded
  upstream payloads.
- Add SARIF export for CI code-scanning integrations.
- Add CSV/JSON import of previous inventories for offline comparison.
- Improve transitive graph fidelity for Maven and Gradle (dependency trees).
- Add configurable license policy and policy violation reporting.

## Mid term

- Optional API token authentication and an explicit "expose to network" mode.
- Persistent, database-backed rate limiting for multi-process deployments.
- Docker image and Compose setup with a non-root user and read-only mounts.
- Support for more ecosystems (Go modules, Composer, NuGet).
- Scheduled rescans and change notifications (webhook/email).
- Signed SBOM/report output (in-toto/Sigstore).

## Long term

- Organization workspaces, projects and trend dashboards.
- VEX import/export to suppress non-exploitable findings.
- Reachability hints from static analysis (opt-in, never executing code).
- Pluggable vulnerability sources beyond OSV/NVD.
- Public API stability guarantees and versioned OpenAPI clients.

## Non-goals

- Runtime protection or container image scanning.
- Multi-tenant SaaS operation.
- Executing project builds, tests or install scripts.
