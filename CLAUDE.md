# CLAUDE.md — Supply Chain Guardian (SCG)

Go CLI that prevents supply chain attacks by enforcing **dependency integrity** and **secret least-privilege** in CI/CD pipelines. Ships as a single binary.

Business model: open-source CLI (free) + Platform API (paid subscription at scg.bds421.com).

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
- Module: `gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian`
- Remote: `git@gitlab2024.bds421-cloud.com:bds421/rho/supply-chain-guardian.git`
- Private registry: `GOPRIVATE=gitlab2024.bds421-cloud.com/*`

| Dependency | Module | Purpose |
|---|---|---|
| tkg/v3 | `gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3 v3.1.2` | Temporal knowledge graph engine |
| tkgd | `gitlab2024.bds421-cloud.com/bds421/sigma/tkgd v0.5.8` | Cypher query engine |
| yaml.v3 | `gopkg.in/yaml.v3 v3.0.1` | GitHub Actions workflow parsing |

## Architecture

SCG uses TKG v3 as its data engine. The graph is invisible to users.

- **CLI mode**: MemoryStore (ephemeral, per-run)
- **Daemon mode**: BadgerStore (persistent history)

All graph reads use Cypher via `engine.Execute()`. Mutations use the Go API (`g.AddNode`, `g.AddRelationship`) wrapped in transactions.

### Graph Schema

**Node labels**: Tool, Digest, Step, Secret, Pipeline, Profile, SecretPattern

**Relationship types**: RESOLVES_TO (temporal!), USES, HAS_ACCESS, HAS_PROFILE, REQUIRES, FORBIDS, CONTAINS_STEP

The RESOLVES_TO relationship between Tool and Digest carries temporal validity (ValidFrom/ValidTo). When a tag is hijacked, the old relationship ends and a new one begins — drift detection is a temporal query.

### Package Layout

```
cmd/scg/           CLI entry point (stdlib flag, no frameworks)
graph/
  schema.go        Labels, rel types, SCGGraph, NewGraph(), EnsureIndexes()
  store.go         Store config factory (memory | badger)
  queries.go       Canned Cypher query constants
resolver/
  resolver.go      Resolver interface, Resolution type, Ecosystem enum
  github.go        GitHub Actions tag → commit SHA via API
parser/
  parser.go        Parser interface, ToolRef, SecretRef, WorkflowFile
  workflow.go      GitHub Actions YAML parser
manifest/
  manifest.go      Lockfile data model (JSON)
  lock.go          ReadLockfile / WriteLockfile
  sign.go          Signer/Verifier interfaces, ed25519 implementation
  drift.go         DetectDrift — compare locked vs live
scoper/
  scoper.go        Scope() — Cypher-based policy evaluation
  env.go           ScanEnv(), LooksLikeSecret(), MatchSecrets()
dsm/
  embedded.go      Top 10 profiles + Bootstrap() into graph
  client.go        Platform DSM client stub
platform/
  client.go        Platform API client stub
  types.go         API request/response types
internal/config    SCGConfig from env vars
internal/testutil  TestGraph(t) helper
```

## Key Rules

### Graph API
- Never import `graph.Store` — use `*graph.Graph` only
- Use `tkg_valid_from`/`tkg_valid_to` in relationship props for temporal semantics
- Use `g.BeginTx()` for multi-entity creates (scg init, scg update)
- Create property indexes AFTER bootstrap (labels must be registered first)
- Use `g.ResolveNodeProperty` for `tkg_*` shadow properties, never `GetProperty`
- Parametrize all Cypher queries (`$param`) — no string concatenation of user input

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

## Current State (v0.1.x)

- Scaffold complete: all packages, interfaces, types, CLI skeleton
- Commands print "not yet implemented" — stubs only
- Next: wire `scg init` end-to-end (parse → resolve → graph → lockfile)
- See `tasks/todo.md` for Phase 1 checklist
- See `tasks/todo.platform` for Platform roadmap

## Session Protocol

- Session start: `go build ./...` first, then read `tasks/todo.md`
- Before graph work: review `graph/schema.go` and `graph/queries.go`
- After corrections: update `tasks/lessons.md` with the pattern
- Before marking done: `make check` must pass
- Do not commit — user handles git
