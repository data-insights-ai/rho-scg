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
  exit.go          Exit-code taxonomy (0 clean / 1 finding / 2 operational)
  sarif.go         SARIF 2.1.0 report for GitHub code scanning
resolver/
  resolver.go      Resolver interface, Resolution, Ecosystem, FreshnessReporter
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
  trust.go         PlatformVerifier — pinned platform key, the trust anchor
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
- The registry-calling resolvers now live in `sigma-scg-platform/registry`, not here.
  `rho-scg/resolver` holds only the shared interface (Resolver, Resolution, Ecosystem,
  FreshnessReporter). Do not reintroduce registry HTTP code into this repo.
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

### Trust anchor — DO NOT WEAKEN
- Lockfile signatures verify against `manifest.PlatformPublicKey`, compiled in.
  NEVER verify against the key carried inside the lockfile: an attacker who can
  edit `scg.lock` simply mints their own keypair and re-signs.
- There is no local signing fallback. If the platform cannot sign, `scg init` fails.
  An unverifiable signature is worse than none — it claims a property it lacks.
- Only `ed25519-platform` is accepted. Never re-accept plain `ed25519`.
- `manifest.CanonicalJSON` is the ONLY function that produces signing bytes.
- Overriding the pinned key is build-time only (`-ldflags -X`), never an env var:
  the threat model includes an attacker who can edit the workflow that sets it.

### Failing closed
- Drift (exit 1) and "SCG could not check" (exit 2) are different outcomes.
  Since there is no fallback, conflating them turns a platform outage into a
  false attack report in every customer's pipeline at once.
- Stale platform data is NOT verified data. A digest that matches a lockfile
  built from the same unrefreshed record proves nothing.
- Secret patterns that fail to compile are a hard error, never a skip.
- Installers verify checksums or refuse to install.

## Testing

- TDD: write the failing test first, then implement
- Tests must never touch the network. Inject a signer/resolver instead
  (see `cmd/scg/signer_test.go`).
- `go test ./...` before and after every change
- `go test -race ./...` for concurrent code
- Table-driven tests for edge cases
- Every public function gets a direct test
- Coverage gate: `make cover-gate` (75% total; raise it, never lower it)
- `make ci` runs fmt, vet, lint, build and race tests. `golangci-lint` must stay clean.

## Current State (v0.1.32)

- All 6 commands working: `init`, `check`, `update`, `scope`, `audit`, `intel`
- Signatures anchored to the pinned platform key; no local fallback
- `check` deduplicates references, resolves concurrently (max 8), and reports
  stale platform data as unverified rather than clean
- Exit codes 0/1/2; `--sarif` emits GitHub code-scanning findings
- Atomic lockfile writes, size cap and schema validation on read
- Platform client: retry with backoff, `Retry-After`, sentinel errors, User-Agent
- Registry resolvers moved to the platform repo
- `golangci-lint` clean, race clean, coverage 79%
- Dependencies: golang.org/x/term, gopkg.in/yaml.v3 (all public)

## Session Protocol

- Session start: `go build ./...` first, then read `tasks/todo.md`
- After corrections: update `tasks/lessons.md` with the pattern
- Before marking done: `make check` must pass
- Do not commit — user handles git
