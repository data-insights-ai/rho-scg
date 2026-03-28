# SCG CLI — Phase 1 Task List

## Phase 1a: Foundation (Week 1)

- [x] Project scaffold (go.mod, directories, Makefile, CLAUDE.md)
- [x] Graph schema (graph/schema.go — labels, rel types, NewGraph, EnsureIndexes)
- [x] Store factory (graph/store.go — memory + badger config)
- [x] Cypher query constants (graph/queries.go)
- [x] Resolver interface (resolver/resolver.go)
- [x] Parser interface (parser/parser.go)
- [x] Lockfile data model (manifest/manifest.go)
- [x] Lockfile read/write (manifest/lock.go)
- [x] Signing interface + ed25519 (manifest/sign.go)
- [x] Drift detection types (manifest/drift.go)
- [x] DSM embedded profiles (dsm/embedded.go — top 10)
- [x] Scoper interface (scoper/scoper.go)
- [x] Env scanner (scoper/env.go)
- [x] GitHub resolver (resolver/github.go)
- [x] Workflow parser (parser/workflow.go)
- [x] Platform client stub (platform/)
- [x] Config model (internal/config/)
- [x] Test helpers (internal/testutil/)
- [x] CLI skeleton (cmd/scg/main.go)
- [x] Verify build compiles

## Phase 1b: Working `scg init` (Week 1-2)

- [x] Wire parser: discover + parse workflow files
- [x] Wire resolver: resolve each tool reference via GitHub API
- [x] Wire graph: populate Tool, Digest, Step, Secret, Pipeline nodes
- [x] Wire graph: create RESOLVES_TO (temporal), USES, HAS_ACCESS relationships
- [x] Bootstrap DSM profiles into graph before scan
- [x] Generate lockfile from parsed + resolved data
- [x] Sign lockfile with ed25519 (ephemeral keypair)
- [x] Integration test: `scg init` on a sample workflow (7 tests, mock resolver)
- [x] Verify `scg init` produces correct scg.lock
- [x] Smoke test: `scg init` with real GitHub API resolves actions/checkout@v4, actions/setup-go@v5

## Phase 1c: Working `scg check` (Week 2)

- [x] Read and verify lockfile signature
- [x] Re-resolve each tool reference
- [x] Compare live digests against locked digests
- [x] Report drift with severity levels
- [x] Exit code: 0 = clean, 1 = drift detected
- [x] Integration test: detect simulated tag hijack (3 drift tests: clean, single, multi)
- [x] Smoke test: `scg check` on clean state returns 0

## Phase 1d: Working `scg scope` (Week 2)

- [x] Scan current environment for secret-like variables
- [x] Populate Secret nodes in graph from env scan
- [x] Query graph for forbidden patterns via Cypher
- [x] Report violations (blocked secrets)
- [ ] Integration test: detect PYPI_TOKEN in trivy-scan step

## Phase 1e: Polish (Week 2)

- [x] `scg update` implementation (re-init with overwrite)
- [x] `scg audit` implementation (drift + scope combined report)
- [x] Add --json flag for machine-readable output (init, check, scope, audit)
- [ ] Error messages: clear, actionable, no stack traces
- [ ] Output formatting: colored terminal output
- [ ] Add --strict flag for fail-closed mode
- [ ] Unit tests for all packages (80% coverage gate)
- [ ] Race detector clean (`make test-race`)

## Phase 2: Signing + Additional Ecosystems

- [ ] OIDC keyless signing (GitHub Actions OIDC token)
- [ ] Docker resolver (tag → manifest digest)
- [ ] Dockerfile parser (FROM directives)
- [ ] PyPI resolver (version → hash)
- [ ] npm resolver (version → integrity hash)
- [ ] Expand embedded profiles to top 30
- [ ] IMDS blocker for cloud runners
