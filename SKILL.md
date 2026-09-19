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
- Supports: GitHub Actions, Docker, PyPI, npm

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
Any tool, script, or agent can invoke `scg` as a subprocess and interpret exit codes + stdout. This is the simplest integration path. Exit code 0 = clean, 1 = finding, 2 = SCG could not complete (not a finding; retry).

### As a CI step
GitHub Action (`data-insights-ai/scg-action@v1`), GitLab CI template (planned), or raw `curl | sh` in any CI system.

### Via the SCG Platform API
`GET /v1/resolve/{ecosystem}/{ref}`, `GET /v1/profile/{ecosystem}/{tool}`, `POST /v1/check` (server-side batch check; the CLI verifies locally against `/v1/resolve` and does not use it). REST API with JSON responses. Requires `SCG_API_KEY`.

### When to invoke SCG

An agent or automation should invoke SCG when:
- A user asks to verify or audit their CI/CD supply chain
- A user asks to lock or pin their dependencies
- A user asks about secret exposure in their CI pipeline
- A pull request modifies `.github/workflows/`, `Dockerfile`, `requirements.txt`, `package.json`, or similar CI config files
- Before deploying or merging code that changes CI/CD configuration
- As a pre-merge gate in any automated pipeline

### Machine-readable output

`init`, `check`, `scope` and `audit` support `--json` for structured output:

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
| `SCG_API_KEY` | Recommended | Raises the request budget from 20/hr (anonymous) to your plan's limit |
| `SCG_PLATFORM_URL` | Optional | Platform endpoint; defaults to `https://api.scg.data-insights.ai` |

`GITHUB_TOKEN` is **not** used and not needed. The CLI never calls GitHub,
Docker Hub, npm or PyPI — all resolution goes through the SCG platform, which
holds the registry credentials server-side.

### Exit codes

| Code | Meaning | Agent action |
|---|---|---|
| 0 | Clean — everything verified | Proceed normally |
| 1 | Finding — drift or a secret violation | Report findings, halt pipeline |
| 2 | Operational — SCG could not complete the check | Retry; do **not** report as a finding |

Exit code 2 means the platform was unreachable, the request budget was spent, or
its data was too old to trust. Nothing was detected about the dependencies, so
treating it as a detection turns an SCG outage into a false alarm.

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

- Commands: `init`, `check`, `update`, `scope`, `audit`, `watch`, `unwatch`, `watches`, `intel`, `login`, `logout`
- Both layers through the platform — no local resolvers, no tokens needed:
  - `scg check` → `/v1/resolve` (hash verification)
  - `scg scope` → `/v1/profile` (secret scoping)
- Platform: 32,000+ tools, 30 security profiles
- 119 tests + 4 fuzz targets, race clean

## Limitations

- Go and Helm ecosystems not yet implemented
- 30 security profiles (expanding)
- Lockfiles are signed by the platform and verified against the platform key compiled into the CLI; a signature by any other key is rejected
