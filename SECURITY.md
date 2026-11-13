# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

- Preferred: open a private security advisory on the project's GitHub
  repository ("Security" → "Advisories" → "Report a vulnerability").
- Alternative: contact the maintainers privately through the repository's
  listed maintainer contact.

Include:

- A description of the issue and its impact.
- Steps to reproduce, including a minimal archive/URL/manifest where possible.
- Affected version/commit and configuration (enabled sources, local paths).
- Any suggested mitigation.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment and severity classification within 10 business days.
- A fix or mitigation plan for confirmed issues, coordinated disclosure, and
  credit unless you prefer to remain anonymous.

## Scope

In scope:

- Path traversal, ZIP slip, archive bombs and symlink handling.
- SSRF, URL validation bypass, redirect/token leakage.
- XXE and unsafe deserialization in parsers.
- Injection into HTML/PDF/CSV reports.
- Secret exposure through API responses, logs or the settings file.
- Authentication/authorization bypass — note that the project intentionally has
  no built-in auth and must not be exposed directly to untrusted networks.
- Denial of service through crafted projects or API requests.

Out of scope:

- Findings that require an already-compromised host or operator account.
- Vulnerabilities in dependencies that are already reported upstream (report
  them upstream, or tell us if our usage makes them exploitable).
- Missing hardening that is documented as a known limitation in
  `docs/threat-model.md`.
- Social engineering and physical attacks.

## Safe harbor

We will not pursue legal action for good-faith research that follows this
policy, avoids privacy violations and service disruption, and gives us
reasonable time to fix the issue before public disclosure.
