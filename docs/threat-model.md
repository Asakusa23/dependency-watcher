# Threat model

## Scope and assumptions

Dependency Watcher is designed as a **local, single-user** tool. The default
bind address is `127.0.0.1`, and there is no built-in authentication or
multi-tenancy. It processes untrusted input: uploaded archives, cloned
repositories, manifest/lock files and upstream API responses.

The model assumes:

- The operator controls the host and the data directory.
- The API is not exposed to an untrusted network without an authenticating
  reverse proxy, TLS and additional access controls.
- Vulnerability and registry data are useful but untrusted inputs, not
  authoritative truth.

## Assets

| Asset | Why it matters |
| --- | --- |
| Host filesystem and processes | Archive/repository parsing must never write outside the work directory or execute project code |
| Data directory (`data/`) | Contains scan history, cached advisories and persisted settings |
| API keys (`DW_NVD_API_KEY`, `DW_GITHUB_TOKEN`) | Could grant access to private repositories or higher-rate NVD usage |
| Scan integrity | Reports must reflect what was actually checked, including unknown/error states |
| Outbound network access | SSRF or token leakage could reach unintended hosts |

## Trust boundaries

1. **Browser → API** — untrusted request bodies, query parameters, filenames and
   uploads.
2. **API → upstream services** — OSV.dev, NVD, PyPI, npm, Maven Central,
   crates.io, GitHub API/codeload.
3. **API → local filesystem** — configured local paths, extracted archives,
   SQLite and the settings file.
4. **CLI → backend services** — same trust level as the operator, but still
   validates paths and URLs.

## Threats and mitigations

### T1. Path traversal / ZIP slip during extraction

**Threat:** an archive entry such as `../../.ssh/authorized_keys` writes outside
the extraction root.

**Mitigations:** entries are normalized, absolute paths and drive letters are
rejected, `.`/`..` segments are rejected, the resolved target must remain inside
the destination, symlinks and encrypted entries are rejected, and a single
top-level directory is unwrapped only after extraction.

### T2. Archive bombs and resource exhaustion

**Threat:** a small ZIP expands to fill the disk or exhausts memory/CPU.

**Mitigations:** limits on archive entries (`DW_MAX_ARCHIVE_FILES`), total and
per-file extracted bytes (`DW_MAX_EXTRACTED_BYTES`), upload/archive size
(`DW_MAX_UPLOAD_BYTES`), project files walked, dependency count and dependency
file size. Suspicious compression ratios are rejected, and streamed extraction
verifies the declared size while writing. Content-Length is checked before
uploads are read.

### T3. SSRF and token exfiltration through repository URLs

**Threat:** a crafted URL makes the server fetch an internal address or send the
GitHub token to an attacker-controlled host.

**Mitigations:** only HTTPS is accepted; hosts must match the configured
allow-list; credentials in URLs and non-443 ports are rejected; owner/repo/ref
characters are strictly validated; path traversal segments are rejected.
Outbound URLs are re-validated before each request, hostnames are resolved and
all resolved addresses must be globally routable (private, loopback, link-local,
reserved and multicast addresses are rejected), and redirects are capped and
re-validated. The GitHub token is only attached to GitHub API/codeload
requests.

### T4. XML external entity / parser attacks

**Threat:** malicious Maven metadata or report input triggers XXE or entity
expansion.

**Mitigations:** Maven metadata is parsed with `defusedxml`; no DTD or external
entity processing is enabled. Other structured formats use `json`,
`ruamel.yaml` safe loading and standard TOML parsing.

### T5. Injection into reports

**Threat:** a package name, advisory text or URL injects script into HTML/PDF
reports or breaks CSV.

**Mitigations:** all HTML values are escaped, report links are restricted to
HTTP(S), HTML reports carry a restrictive Content-Security-Policy, CSV fields
are written through the `csv` module, and PDF rendering uses ReportLab drawing
primitives rather than raw HTML.

### T6. Secrets in API responses or logs

**Threat:** API keys leak through settings endpoints or log lines.

**Mitigations:** settings responses expose only `*_configured` booleans; keys
are masked; the settings file is written atomically with mode `0600`; a logging
filter redacts key/token/secret/password/authorization patterns; the GitHub
token is never logged or returned.

### T7. Unauthorized or abusive API use

**Threat:** another local process or a misconfigured proxy floods the API or
starts expensive scans.

**Mitigations:** per-client token-bucket limits for API requests and scans,
higher costs for scan creation and uploads, `Retry-After` responses, CORS
restricted to local development origins, and security headers
(`nosniff`, `DENY`, `no-referrer`, restrictive permissions policy). These are
denial-of-service controls, **not** authentication.

### T8. Malicious project content

**Threat:** parsing a repository executes code or follows links outside the
project.

**Mitigations:** the scanner reads dependency files as data only and never
executes project code, hooks or build scripts. Walk limits apply; symlinked
archive entries are rejected. Local path scans are restricted to absolute
directories and can be disabled with `DW_ALLOW_LOCAL_PATHS=false`.

### T9. Upstream data poisoning or outages

**Threat:** a compromised or unavailable source produces false negatives or
crashes the scan.

**Mitigations:** responses are size-limited, parsed defensively and cached;
failures are converted to `ERROR`/`UNKNOWN` states with warnings rather than
`safe`; withdrawn advisories are excluded; missing advisory details are
reported; scans continue when a non-critical source is unavailable.

### T10. Database and file integrity

**Threat:** orphaned records, partial writes or tampered scan history.

**Mitigations:** foreign keys with `ON DELETE CASCADE`, WAL mode, transactional
session usage, explicit cleanup of managed work directories in `finally`, and
scan deletion that removes associated findings. There is no cryptographic
signing of history; treat the database as operator-trusted.

## Residual risks

- **No authentication/authorization** — exposing the API beyond localhost is
  unsupported without an external auth layer.
- **Local path scans** — a user who can call the API can ask it to read any
  directory the service account can read. Disable local paths if this is
  unacceptable.
- **Rate limits are in-memory** — they reset on restart and are per-process.
- **DNS rebinding** — addresses are validated at request time, but a TOCTOU
  window remains between resolution and connection. The strict host allow-list
  makes exploitation impractical for the supported sources.
- **Third-party data quality** — false negatives/positives from OSV.dev, NVD or
  registries are possible and are reflected in coverage and limitation notices.
- **No SBOM/report signing** — generated artifacts are not attested.

## Out of scope

- Multi-user access control, SSO and audit trails.
- Sandboxing the backend process itself (use containers/OS controls).
- Scanning container images or running applications.
- Protecting against a compromised host or operator account.
