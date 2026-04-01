# CLAUDE.md — Supply Chain Guardian (SCG)

Go CLI that prevents supply chain attacks by enforcing **dependency integrity** and **secret least-privilege** in CI/CD pipelines. Ships as a single binary.

Business model: open-source CLI (free) + Platform API (paid subscription at scg.data-insights.ai).

## Commands

```bash
make build          # compile scg binary
make test           # unit tests (-short, no cache)
make test-race      # race detector
make check          # pre-commit: fmt-check + vet + build + test
make ci             # full: fmt-check + vet + build + test-race
make cover          # coverage report -> coverage.html
make fmt            # format code
make clean          # remove binary + coverage
```

```bash
# CLI usage
./scg init                        # scan workflows, resolve deps, write scg.lock
./scg init --workflows DIR        # custom workflow directory
./scg check                       # validate scg.lock against live (exit 0|1)
./scg check --lockfile PATH       # custom lockfile path
./scg update                      # re-resolve all, update scg.lock
./scg scope --step NAME           # audit + sanitize env for step
./scg audit                       # full report: drift + secret exposure
./scg version                     # print version
```

## Stack

- Go 1.26.1
- Module: `github.com/data-insights-ai/rho-scg`
- Remote: `git@github.com:data-insights-ai/rho-scg.git`

| Dependency | Module | Purpose |
|---|---|---|
| yaml.v3 | `gopkg.in/yaml.v3 v3.0.1` | GitHub Actions workflow parsing |
| x/term | `golang.org/x/term` | Terminal detection for colored output |

## Architecture

SCG is a platform-only CLI. All resolution and profile queries go through the SCG Platform API at `api.scg.data-insights.ai`. The CLI has no local graph, no local resolvers, and no registry credentials.

### Package Layout

```
cmd/scg/           CLI entry point (stdlib flag, no frameworks)
resolver/
  resolver.go      Resolver interface, Resolution type, Ecosystem enum
parser/
  parser.go        Parser interface, ToolRef, SecretRef, WorkflowFile
  workflow.go      GitHub Actions YAML parser
  dockerfile.go    Dockerfile FROM directive parser
  npm.go           package-lock.json parser (v1/v2/v3)
  pypi.go          requirements.txt parser
manifest/
  manifest.go      Lockfile data model (JSON)
  lock.go          ReadLockfile / WriteLockfile
  sign.go          Signer/Verifier interfaces, ed25519 implementation
  drift.go         DetectDrift — compare locked vs live
scoper/
  env.go           ScanEnv(), LooksLikeSecret(), MatchSecrets()
platform/
  client.go        Platform API client
  types.go         API request/response types
  resolver.go      Platform-backed resolver implementation
internal/config    SCGConfig from env vars
internal/testutil  Test helpers
```

## Key Rules

### Versioning — NEVER increase minor or major version
- Only use patch versions (e.g., v0.1.26 → v0.1.27)
- NEVER bump minor (v0.1.x → v0.2.x) or major version without explicit user approval
- The user decides when a minor or major version bump is warranted
- Ask before tagging if unsure

### Business Model — THE MOST IMPORTANT RULE
- The platform (api.scg.data-insights.ai) is the ONLY resolver. Always. No exceptions.
- The CLI NEVER calls GitHub, Docker Hub, PyPI, or npm APIs directly.
- GITHUB_TOKEN is NOT used by the CLI. It is used by the platform's crawler on the server.
- There is NO fallback to local resolution. If the platform is down, the check fails.
- If a tool is not in the platform database, the answer is "not found" — not "let me ask GitHub."
- The user does NOT need a GitHub token, a Docker Hub account, or any registry credentials.
- ALL resolution goes through the platform. That is the product. That is the business.
- Never add code that bypasses the platform. Never add "local resolution" as a fallback.
- Rate tiers: 20/hr anonymous, 100/hr free account, 5000/hr Pro, 50000/hr Enterprise.

### Code Style
- Files under 500 lines
- No emojis in code or output
- `log/slog` for structured logging
- Every error return must be checked and handled
- No external dependencies without discussion

### Security
- Every input is untrusted — validate and reject early
- No credentials in source code or logs
- `subtle.ConstantTimeCompare` for secret comparison
- Generic error messages outward, detailed logs inward
- Run `govulncheck ./...` for dependency CVEs

## Testing

- TDD: write the failing test first, then implement
- `go test ./...` before and after every change
- `go test -race ./...` for concurrent code
- Table-driven tests for edge cases
- Every public function gets a direct test
- Coverage gate: 80% per package

## Current State (v0.1.30)

- All 5 commands working: `init`, `check`, `update`, `scope`, `audit`
- Both layers through the platform:
  - `scg check` → platform `/v1/resolve` (hash verification)
  - `scg scope` → platform `/v1/profile` (secret scoping)
- Multi-ecosystem parsing: GitHub Actions, Docker, npm, PyPI
  - `scg init` auto-discovers `package-lock.json`, `requirements.txt`, `Dockerfile` in repo root
  - Per-ecosystem resolver routing via `buildResolvers()` map
- No local resolvers. No GITHUB_TOKEN. No fallback.
- Platform: api.scg.data-insights.ai (32,000+ tools, 30 profiles)
- CLI install: scg.data-insights.ai
- Quiet by default, `--verbose` for logs
- 130 tests + 6 fuzz targets, race clean
- Binary size: 6.4 MB (zero graph dependencies)
- Dependencies: golang.org/x/term, gopkg.in/yaml.v3 (all public)
- Next: expand profile database (30 → hundreds)

## Session Protocol

- Session start: `go build ./...` first, then read `tasks/todo.md`
- After corrections: update `tasks/lessons.md` with the pattern
- Before marking done: `make check` must pass
- Do not commit — user handles git
