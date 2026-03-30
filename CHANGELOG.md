# Changelog

All notable changes to Supply Chain Guardian are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.27] - 2026-03-30

### Changed
- **Removed graph dependencies**: eliminated `tkg/v3` and `tkgd` from CLI — dead code after platform-only pivot. Zero private dependencies. Builds anywhere.
- **Module path**: migrated to `github.com/data-insights-ai/rho-scg`
- **Domain migration**: all URLs from `scg.bds421.com` to `scg.data-insights.ai`
- **Binary size**: 18MB → 6.4MB (removed BadgerDB, protobuf, OpenTelemetry transitive deps)
- **Documentation rewrite**: all `.md` files updated for platform-only architecture
- **Sensitive data removed**: no server IPs or internal paths in open-source docs

### Removed
- `graph/` package (schema, store, queries)
- `dsm/` package (embedded profiles, client stub)
- `scoper/scoper.go` (Cypher-based Scope function, replaced by platform API)
- `vendor/` directory (all deps now public)

## [0.1.26] - 2026-03-30

### Security fixes
- **Partial verification fails (exit 1)**: if ANY tool cannot be verified (rate limit, platform down, not found), `scg check` now exits 1. Verification is all-or-nothing. Previously partial verification (95 of 100 tools) exited 0 — a security gap.

### Architecture cleanup
- **Removed local graph from init**: `scg init` no longer creates a TKG graph, bootstraps DSM, or populates nodes. Parse → resolve via platform → lockfile → sign → write. 508 → 240 lines.
- **Removed local graph from audit**: `scg audit` now uses platform `/v1/profile` for scoping (same as `scg scope`). No local graph, no DSM bootstrap, no Cypher queries. Consistent with the platform-only architecture.
- **All commands use platform only**: init, check, update, scope, audit — none create local graphs or call registries directly.

## [0.1.24] - 2026-03-30

### Changed
- **Both layers through the platform**: `scg check` (hashes) AND `scg scope` (profiles) now query the platform exclusively. No local graph, no DSM bootstrap, no Cypher queries in the CLI.
- **scg scope rewritten**: single platform API call to `/v1/profile` + local env scan + regex match. Removed 150+ lines of graph setup code.
- **No local resolvers anywhere**: removed all `NewGitHubResolver`, `NewDockerResolver`, `NewPyPIResolver`, `NewNPMResolver` from CLI. Removed `GITHUB_TOKEN` from config.
- **No fallback**: deleted `resolver/fallback.go`. Platform is the only resolver.
- **Errors always shown**: fixed silent error swallowing in main.go.
- **ProfileResponse type fixed**: matches actual platform API response (strings not objects, `forbidden_patterns` not `forbidden_secrets`).

## [0.1.23] - 2026-03-29

### Changed
- Quiet by default, `--verbose` for detailed logs
- Proper `--verbose` flag registered in every subcommand
- Clean warning messages (root cause only)
- Honest verification (fails when all tools skipped)
- Platform-first resolver (CLI queries api.scg.data-insights.ai by default)
- No GITHUB_TOKEN needed

## [0.1.17] - 2026-03-29

### Added
- **Platform integration**: `SCG_API_KEY=xxx scg check` routes all resolution through the SCG Platform API at `api.scg.data-insights.ai`. Pre-computed hashes, no registry rate limits.
- **Platform resolver** (`platform/resolver.go`): implements `resolver.Resolver` interface backed by platform API GET `/v1/resolve`.
- **Platform client** (`platform/client.go`): full implementation with GET, POST, auth headers, 10MB response limits, error handling for 401/403/404/429.
- **Response caching**: 5-minute TTL in-memory cache for platform API responses. Avoids redundant calls for the same tool within a check run.
- **Graceful fallback**: when `SCG_API_KEY` is set but platform is unavailable, `scg check` continues with warnings (partial failure). When not set, uses local resolvers as before.
- **`platform/types.go`**: `CheckResponse`, `DriftEntry` types for batch check API.

### Changed
- `buildResolvers()` in `check.go` auto-selects platform resolvers when `SCG_API_KEY` is set, local resolvers otherwise.
- Deploy docs updated for separate subdomains: `scg.data-insights.ai` (CLI), `api.scg.data-insights.ai` (platform).

## [0.1.14] - 2026-03-29

### Added
- `install.sh` — cross-platform install script (detects OS/arch, downloads binary, verifies checksum)
- `action.yml` — GitHub Action wrapper (check, scope, init, audit modes with all flags)
- `.goreleaser.yml` — cross-compile config for linux/darwin amd64/arm64 with checksums
- `tasks/todo.cli` — distribution task list (action, releases, install script, homebrew)

## [0.1.13] - 2026-03-29

### Fixed
- **Scope actually sanitizes**: `scg scope --sanitize` calls `os.Unsetenv()` for blocked secrets. Without flag, audit-only. README updated to match.
- **Graph sanity check**: `verifyGraphState()` runs after `populateGraph()` — checks pipeline and tool node counts match expectations. Fails with clear error if graph is incomplete.
- **Lockfile duplicate entries**: Steps with same name across different jobs (e.g., `test:checkout` and `security:checkout`) no longer produce duplicate tool entries. Fixed by keying on `job:step` instead of `step` alone. Found by dogfooding.
- **Profile coverage warning**: `scg scope` warns when a tool has no DSM profile loaded, with profile count for debugging.

### Added
- `.github/workflows/ci.yml` — SCG's own CI workflow for dogfooding
- `--sanitize` flag on `scg scope` (default: audit-only)
- Dogfooded `scg init` + `scg check` + `scg audit` on SCG's own repo — all pass

## [0.1.12] - 2026-03-29

### Fixed
- **No silently swallowed errors**: DSM `Bootstrap()` now validates all profile regex patterns at startup and returns profile count for sanity checking. Audit scope failures are now hard errors, not warnings. Lockfile read/drift errors in audit are hard errors.
- **DSM profile validation**: `ValidateProfiles()` checks for empty references, empty ecosystems, and invalid regex at bootstrap time — catches configuration bugs before graph population.
- **Documented CLI-to-platform limitations**: Added explicit section in `tasks/todo.platform` listing what the CLI can't do and how the platform solves each gap.

## [0.1.11] - 2026-03-29

### Fixed (second security review)
- **Canonical JSON signing**: Sign and verify now use shared `canonicalJSON()` — eliminates risk of serialization divergence between signing and verification paths
- **HTTP response body size limits**: All resolver HTTP clients capped at 10MB via `io.LimitReader` — prevents OOM from malicious registries
- **URL path encoding**: All resolver URLs use `url.PathEscape()` for package names, versions, owners — prevents path traversal injection
- **Audit uses all resolvers**: `scg audit` now checks Docker, PyPI, npm drift (was only GitHub)
- **Lockfile path validation**: `WriteLockfile` rejects paths containing `..` — prevents directory traversal via `--lockfile` flag
- **Honest scoper documentation**: `ScanEnv()` docstring clarifies it only identifies secrets, does not sanitize (caller's responsibility)
- **Docker ref parsing coupling documented**: Workflow parser's docker:// handling notes it must stay consistent with `resolver.parseDockerRef()`

## [0.1.10] - 2026-03-29

### Fixed (security review findings)
- **Signatures now mandatory by default.** Unsigned lockfiles fail `scg check`. Use `--no-verify` to skip (not recommended). Previously signatures were optional (default fail-open).
- **All 4 ecosystem resolvers registered in `scg check`.** Docker, PyPI, npm drift is now detected. Previously only GitHub Actions was checked — other ecosystems were silently skipped.
- **`docker://` images in workflows now parsed.** `uses: docker://alpine:3.19` is extracted as a Docker ecosystem dependency. Previously explicitly skipped with a TODO comment.
- **Partial failure in drift detection.** If one tool can't be resolved (API down, rate limited), other tools are still checked. Warnings report which tools were skipped. Previously one failure killed the entire check.
- **Removed OIDC signing theater.** `oidc+ed25519` signature algorithm removed — it embedded unverified OIDC claims, providing false sense of identity binding. CLI now uses honest ephemeral ed25519. Identity-bound signing (OIDC + JWKS verification) will be a platform-tier feature with real cryptographic verification.
- **`scg check` no longer bootstraps graph.** It reads the lockfile and re-resolves directly — no wasted DSM profile loading.

### Changed
- `--strict` flag renamed to `--no-verify` (inverted default: signatures now required)
- `VerifyOIDCClaims()` retained for platform-tier use (validates exp, nbf, issuer)
- `OIDCSigner` type removed (was security theater without JWKS verification)
- `Ed25519Verifier` only accepts `"ed25519"` algorithm (removed `"oidc+ed25519"`)

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
- All URLs updated to `scg.data-insights.ai`, email to `security@data-insights.ai`
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
- Platform URL updated to `scg.data-insights.ai` (from placeholder)

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
