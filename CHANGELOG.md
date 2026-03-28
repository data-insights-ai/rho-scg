# Changelog

All notable changes to Supply Chain Guardian are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
