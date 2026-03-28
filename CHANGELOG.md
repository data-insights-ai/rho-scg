# Changelog

All notable changes to Supply Chain Guardian are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.9] - 2026-03-28

### Added
- **Concurrent resolver tests**: 20 goroutines resolving different tools, 10 resolving same tool, parse function thread safety (200 concurrent calls), all race-clean
- **OIDC JWT verification**: `VerifyOIDCClaims()` validates expiration, not-before (with 30s skew tolerance), issuer presence. 6 new tests (valid, expired, not-yet-valid, missing issuer, no expiration, skew tolerance)
- **Real registry integration tests** (build tag `integration`): Docker Hub alpine+nginx, PyPI requests, npm express — all verified against live registries
- **Filesystem edge cases**: read-only directory, symlink traversal, /dev/null, long paths, overwrite behavior
- **Fuzz tests**: Go native fuzzing for workflow parser, Dockerfile parser, and all reference parsers (action, Docker, PyPI, npm). Millions of random inputs, zero panics found.

122 tests (up from 101), race detector clean, 4 fuzz targets.

## [0.1.8] - 2026-03-28

### Added
- 46 production-grade tests (101 total, up from 55):
  - **Network failure tests**: resolver timeout, 404, 500, rate limit, malformed JSON, empty response, context cancellation
  - **Parser adversarial tests**: empty files, null bytes, binary content, deeply nested YAML, malformed YAML, long image refs, control chars, build arg skip
  - **Graph correctness tests**: node creation verification, Cypher query results, secret violation detection, dedup behavior, parameter injection defense, query parsing
  - **Manifest security tests**: empty JSON, invalid JSON, truncated, binary content, wrong key, algorithm confusion, malformed base64, short keys, deterministic signing, empty lockfile, empty hash drift

### Fixed
- **Security bug found by tests**: GitHub resolver accepted empty SHA hashes without error. Now validates SHA is non-empty before returning.

## [0.1.7] - 2026-03-28

### Added
- **Docker ecosystem**: Dockerfile parser (FROM directives) + Docker Registry V2 resolver (tag -> manifest digest)
- **PyPI ecosystem**: resolver (version -> SHA256 via PyPI JSON API)
- **npm ecosystem**: resolver (version -> integrity hash via npm registry), supports scoped packages
- **OIDC keyless signing**: auto-detects OIDC tokens from GitHub Actions, GitLab CI, or generic env. Generates ephemeral ed25519 keypair, embeds OIDC issuer + subject in signature. Falls back to ed25519 if no OIDC available.
- Expanded DSM profiles from 10 to 30: added AWS configure-credentials, GCP auth, Azure login, Docker login/setup-buildx/metadata, GitHub CodeQL, Codecov, SonarCloud, HashiCorp setup-terraform, Helm chart-releaser, softprops gh-release, Slack notification, GoReleaser, peter-evans create-pull-request, actions setup-java/setup-dotnet/github-script/create-release/deploy-pages
- Documentation: `doc/oidc-signing.md` — complete guide to keyless signing
- 17 new tests (parser: 7 Dockerfile, resolver: 7 Docker/PyPI/npm, manifest: 3 OIDC)

### Changed
- Signing auto-selects: OIDC keyless in CI, ed25519 fallback locally
- Ed25519 verifier now accepts both `ed25519` and `oidc+ed25519` algorithms
- README ecosystems table updated to reflect implemented resolvers

## [0.1.6] - 2026-03-28

### Added
- `--strict` flag on check and scope: unsigned lockfiles rejected, warnings become errors
- Colored terminal output: green checkmarks, red X marks, yellow warnings (auto-detect terminal via x/term)
- Per-package unit tests: parser (4), resolver (4), manifest/lock (3), manifest/sign (5),
  manifest/drift (4), scoper (4), graph (4), cmd (10) = 38 total tests
- Race detector clean (`go test -race ./...`)

## [0.1.5] - 2026-03-28

### Added
- `scg scope` working end-to-end: parse workflow, bootstrap DSM, scan environment,
  populate graph with secret nodes, query for forbidden pattern violations
- `scg update` working: re-resolves all dependencies and rewrites lockfile
- `scg audit` working: combines drift detection + secret exposure analysis in one report
- `--json` flag on init, check, scope, audit for machine-readable output
- 3 drift simulation tests: clean check, single-tool tamper, multi-tool tamper

### Changed
- README: removed out-of-scope attacks (xz, 3CX, SolarWinds) — focus on what SCG does
- Coverage matrix cleaned up: 7 direct attacks, no indirect entries

## [0.1.4] - 2026-03-28

### Added
- `scg init` working end-to-end: discover workflows, parse GitHub Actions YAML,
  resolve tool references via GitHub API, populate TKG temporal knowledge graph,
  sign with ed25519, write `scg.lock`
- `scg check` working end-to-end: read lockfile, verify signature, re-resolve
  dependencies, detect drift, exit 0 (clean) or 1 (drift detected)
- Graph population with deduplication: same tool in multiple steps creates one
  Tool node, one Digest node, with correct USES/RESOLVES_TO/HAS_ACCESS relationships
- DSM profile linking: versioned tools (e.g., `trivy-action@v1`) linked to
  bootstrap security profiles via base reference matching
- 7 integration tests with mock resolver (no network calls)
- Sample workflow fixture (`internal/testutil/testdata/ci.yml`)
- Smoke-tested with real GitHub API (actions/checkout@v4, actions/setup-go@v5)

## [0.1.3] - 2026-03-28

### Changed
- README restructured: Quick Start moved above the fold, funnel structure (What → Install → Why → Deep dive)
- Attack tables sorted chronologically (newest first), split into "Direct" vs "Outside Scope" with honest assessments
- Removed overclaims on SolarWinds, 3CX, xz/liblzma — clearly marked as indirect/outside SCG's scope
- All URLs updated to `scg.bds421.com`, email to `security@bds421.com`
- CLAUDE.md consolidated with full package layout, exact dependency versions, session protocol

### Added
- SKILL.md for agent/tool discovery — describes CLI, library, CI, and API integration paths
- CONTRIBUTING.md for contributor onboarding

## [0.1.2] - 2026-03-28

### Added
- Comprehensive "Why SCG?" section with kill chain analysis for 9 real-world supply chain attacks:
  tj-actions/changed-files, reviewdog, Codecov, xz/liblzma, SolarWinds, ua-parser-js,
  event-stream, PyTorch dependency confusion, PyPI typosquatting campaigns
- Per-attack kill chain diagrams showing exactly where SCG breaks each attack
- Coverage matrix: digest pinning stops 9/9, secret scoping provides defense-in-depth for 3

### Changed
- Platform URL updated to `scg.bds421.com` (from placeholder)

## [0.1.1] - 2026-03-28

### Added
- Project scaffold with full package structure
- Graph schema: 7 node labels, 7 relationship types (temporal RESOLVES_TO)
- TKG v3 integration: in-memory (CLI) and BadgerDB (daemon) graph backends
- Cypher query engine integration for policy evaluation
- CLI skeleton with `init`, `check`, `update`, `scope`, `audit`, `version` commands
- GitHub Actions workflow parser (`.github/workflows/*.yml`)
- GitHub Actions resolver (tag/branch -> commit SHA via GitHub API)
- Ed25519 lockfile signing with verification
- Drift detection engine (compare locked vs. live digests)
- Secret scoping engine with Cypher-based policy queries
- Environment variable scanner for secret-like variables
- Embedded DSM security profiles for top 10 GitHub Actions
- `scg.lock` lockfile format (JSON, human-readable, git-diffable)
- Platform API client stubs (for future paid tier)
- Configuration via environment variables
- Comprehensive documentation: architecture, security model, getting started, lockfile spec
