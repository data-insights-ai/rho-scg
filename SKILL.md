# SKILL.md — Supply Chain Guardian (SCG)

## Identity

- **Name:** Supply Chain Guardian
- **Short name:** scg
- **Version:** 0.1.2
- **Description:** Prevents CI/CD supply chain attacks by enforcing dependency integrity (digest pinning) and secret least-privilege (scoped environment variables).
- **License:** Apache-2.0
- **Repository:** https://github.com/data-insights-ai/rho-scg

## Capabilities

SCG provides two independent defense layers for CI/CD pipelines:

### Layer 1: Dependency Integrity
- Resolves mutable references (tags, branches, version strings) to immutable content digests
- Detects drift: when a tag points to a different commit than when it was locked
- Supports: GitHub Actions, Docker (planned), PyPI (planned), npm (planned)

### Layer 2: Secret Scoping
- Evaluates which secrets each CI step should have access to
- Uses embedded security profiles (Dependency Security Model) with forbidden patterns
- Strips unauthorized secrets from the environment before a step runs

## CLI Interface

```
scg init [--workflows DIR] [--lockfile PATH]
  Scan CI/CD workflow files, resolve all dependency references to immutable
  digests, and write a signed lockfile (scg.lock).
  Exit: 0 = success, 1 = error

scg check [--lockfile PATH]
  Validate the lockfile against live resolution. Detects tag hijacking,
  dependency confusion, and unauthorized changes.
  Exit: 0 = clean, 1 = drift detected

scg update [--lockfile PATH]
  Re-resolve all dependencies and update the lockfile. Use after
  intentionally updating a dependency version.
  Exit: 0 = success, 1 = error

scg scope --step NAME
  Audit the current environment against the security profile for the
  named step's tool. Reports forbidden secrets and optionally sanitizes
  the environment.
  Exit: 0 = clean, 1 = violations found

scg audit [--workflows DIR]
  Full security report combining dependency integrity check and secret
  exposure analysis across all pipeline steps.
  Exit: 0 = clean, 1 = issues found

scg version
  Print version string.
```

## Integration

SCG is designed to be consumed in multiple ways — not just as a CLI for humans.

### As a CLI subprocess
Any tool, script, or agent can invoke `scg` as a subprocess and interpret exit codes + stdout. This is the simplest integration path. Exit code 0 = clean, 1 = issues found.

### As a CI step
GitHub Action (`data-insights-ai/scg-action@v1`), GitLab CI template (planned), or raw `curl | sh` in any CI system.

### Via the SCG Platform API
`GET /v1/resolve/{ecosystem}/{ref}`, `GET /v1/profile/{ecosystem}/{tool}`, `POST /v1/check` (planned). REST API with JSON responses. Requires `SCG_API_KEY`.

### When to invoke SCG

An agent or automation should invoke SCG when:
- A user asks to verify or audit their CI/CD supply chain
- A user asks to lock or pin their dependencies
- A user asks about secret exposure in their CI pipeline
- A pull request modifies `.github/workflows/`, `Dockerfile`, `requirements.txt`, `package.json`, or similar CI config files
- Before deploying or merging code that changes CI/CD configuration
- As a pre-merge gate in any automated pipeline

### Machine-readable output

All commands support `--json` flag (planned) for structured output:

```json
{
  "status": "drift_detected",
  "exit_code": 1,
  "findings": [
    {
      "type": "critical_drift",
      "ecosystem": "github_action",
      "reference": "aquasecurity/trivy-action@v1",
      "locked_hash": "sha256:57a97c7e...",
      "live_hash": "sha256:ff00bad1...",
      "detail": "Tag hijack: same tag, different commit"
    }
  ]
}
```

### Environment requirements

| Variable | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | Recommended | Avoids GitHub API rate limits (60/hr without, 5000/hr with) |
| `SCG_API_KEY` | Optional | Enables SCG Platform (pre-computed hashes, curated profiles) |

### Exit codes

| Code | Meaning | Agent action |
|---|---|---|
| 0 | Clean — no issues found | Proceed normally |
| 1 | Issues found (drift, violations) | Report findings, halt pipeline |
| 2 | Configuration error | Fix config, retry |

## Supported Ecosystems

| Ecosystem | Config files | Status |
|---|---|---|
| GitHub Actions | `.github/workflows/*.yml` | Implemented |
| Docker | `Dockerfile` | Implemented |
| PyPI | `requirements.txt`, `pyproject.toml` | Implemented |
| npm | `package.json`, `package-lock.json` | Implemented |
| Go | `go.mod`, `go.sum` | Planned |
| Helm | `Chart.yaml` | Planned |

## Data Model

SCG models dependencies as a temporal knowledge graph:

- **Nodes:** Tool, Digest, Step, Secret, Pipeline, Profile, SecretPattern
- **Key relationship:** `RESOLVES_TO` (Tool -> Digest) is temporal — carries ValidFrom/ValidTo timestamps enabling drift detection over time

## Current Status (v0.1.24)

- All 5 commands working: `init`, `check`, `update`, `scope`, `audit`
- Both layers through the platform — no local resolvers, no tokens needed:
  - `scg check` → `/v1/resolve` (hash verification)
  - `scg scope` → `/v1/profile` (secret scoping)
- Platform: 32,000+ tools, 30 security profiles
- 119 tests + 4 fuzz targets, race clean

## Limitations

- Go and Helm ecosystems not yet implemented
- 30 security profiles (expanding)
- Identity-bound signing (OIDC + JWKS) planned for platform tier
- Ephemeral ed25519 keys — no chain of trust across lockfile versions
