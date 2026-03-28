# CLAUDE.md — Supply Chain Guardian (SCG)

Go CLI that prevents supply chain attacks by enforcing **dependency integrity** and **secret least-privilege** in CI/CD pipelines. Ships as a single binary.

Business model: open-source CLI (free) + Platform API (paid subscription).

## Commands

```bash
make build          # compile scg binary
make test           # unit tests
make test-race      # race detector
make check          # pre-commit: fmt-check + vet + build + test
make ci             # full: fmt-check + vet + build + test-race
make cover          # coverage report -> coverage.html
```

```bash
# CLI usage
./scg init           # scan workflows, resolve deps, write scg.lock
./scg check          # validate scg.lock against live (exit 0|1)
./scg update         # re-resolve all, update scg.lock
./scg scope --step X # audit + sanitize env for step X
./scg audit          # full report across all steps
./scg version        # print version
```

## Stack

- Go 1.26.1
- Module: `gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian`
- Private registry: `GOPRIVATE=gitlab2024.bds421-cloud.com/*`

| Dependency | Module | Purpose |
|---|---|---|
| tkg/v3 | `gitlab2024.bds421-cloud.com/bds421/rho/tkg/v3` | Temporal knowledge graph engine |
| tkgd | `gitlab2024.bds421-cloud.com/bds421/sigma/tkgd` | Cypher query engine |
| yaml.v3 | `gopkg.in/yaml.v3` | GitHub Actions workflow parsing |

## Architecture

SCG uses TKG v3 as its data engine. The graph is invisible to users.

- **CLI mode**: MemoryStore (ephemeral, per-run)
- **Daemon mode**: BadgerStore (persistent history)

All graph reads use Cypher via `engine.Execute()`. Mutations use the Go API (`g.AddNode`, `g.AddRelationship`) wrapped in transactions.

### Graph Schema

**Node labels**: Tool, Digest, Step, Secret, Pipeline, Profile, SecretPattern
**Relationship types**: RESOLVES_TO (temporal!), USES, HAS_ACCESS, HAS_PROFILE, REQUIRES, FORBIDS, CONTAINS_STEP

The RESOLVES_TO relationship between Tool and Digest carries temporal validity (ValidFrom/ValidTo). When a tag is hijacked, the old relationship ends and a new one begins — drift detection is a temporal query.

### Key Rules

- Never import `graph.Store` — use `*graph.Graph` only
- Use `tkg_valid_from`/`tkg_valid_to` in relationship props for temporal semantics
- Use `g.BeginTx()` for multi-entity creates (scg init, scg update)
- Create property indexes AFTER bootstrap (labels must be registered first)
- Use `g.ResolveNodeProperty` for `tkg_*` shadow properties, never `GetProperty`
- Parametrize all Cypher queries (no string concatenation of user input)

### Package Layout

```
cmd/scg/         CLI entry point
graph/           TKG schema, store factory, Cypher queries
resolver/        Resolver interface + GitHub Actions implementation
parser/          Parser interface + GitHub Actions YAML parser
manifest/        Lockfile model, read/write, signing, drift detection
scoper/          Secret scoping policy engine
dsm/             Dependency Security Model — profiles
platform/        Platform API client (paid tier)
internal/config  Configuration
internal/testutil Test helpers
```

## Testing

- TDD: write the test first, implement to make it pass
- `go test ./...` before and after every change
- Table-driven tests for edge cases
- Every public function gets a direct test
- Coverage gate: 80% per package

## Security

- Never trust external data — validate and reject early
- Parametrized Cypher queries always — never concatenate user input
- No credentials in source code or logs
- `subtle.ConstantTimeCompare` for secret comparison
- Generic error messages outward, detailed logs inward
