# SCG CLI — Task List

## Done

### Foundation + Commands
- [x] All 5 commands: init, check, update, scope, audit
- [x] 4 parsers: GitHub Actions YAML, Dockerfile, PyPI, npm
- [x] Lockfile: JSON format, ed25519 signing, verification
- [x] Platform-only resolution for all commands
- [x] 30 security profiles (platform-managed)
- [x] 119 tests + 4 fuzz targets, race clean

### Platform-Only Architecture
- [x] `scg check` → platform `/v1/resolve` (hash verification)
- [x] `scg scope` → platform `/v1/profile` (secret scoping)
- [x] No local resolvers. No GITHUB_TOKEN. No fallback.
- [x] Platform client works without API key (20/hr anonymous)
- [x] Response caching (5 min TTL)

### Distribution
- [x] Install script: scg.data-insights.ai/install.sh
- [x] Cross-compiled binaries: linux/darwin amd64/arm64
- [x] GitHub Action wrapper: action.yml
- [x] Landing page: scg.data-insights.ai with Data Insights AI branding

## Current — Multi-Ecosystem Lockfile Parsing

Platform v0.3.0 now crawls npm, PyPI, Docker Hub and tracks dependency graphs.
The CLI needs lockfile parsers so `scg init` and `scg check` work beyond GitHub Actions.

### Parsers

- [x] **parser/npm.go** — Parse `package-lock.json`
  - Implements `Parser` interface (`Supports`, `Parse`)
  - Handles lockfile v2/v3 (`packages` field) and v1 (`dependencies` fallback with recursion)
  - Extracts `name@version` as ToolRef with ecosystem `"npm"`
  - Scoped packages: `@scope/pkg` with Owner extraction
  - 8 tests + 1 fuzz target

- [x] **parser/pypi.go** — Parse `requirements.txt`
  - Supports `requirements.txt`, `requirements-*.txt`
  - Parses `==`, `>=`, `~=` version operators
  - Strips comments, options, extras, environment markers
  - Reference format: `name@version` with ecosystem `"pypi"`
  - 10 tests + 1 fuzz target

### Init command

- [x] **cmd/scg/init.go** — Multi-parser discovery
  - `discoverLockfiles(repoRoot)` — finds `package-lock.json`, `requirements*.txt`, `Dockerfile`
  - `parseWithMultiParser(parsers, paths)` — routes files to matching parser via `Supports()`
  - Existing workflow discovery unchanged (all prior tests pass)
  - Lockfile results appended after workflow parsing

- [x] **Multi-resolver refactor** — `doInit`, `doAudit`, `resolveTools` accept `map[resolver.Ecosystem]resolver.Resolver`
  - Reuses `buildResolvers()` from `check.go`
  - Per-tool ecosystem routing in `resolveTools`

### Tests

- [x] npm: empty lockfile, root-only, scoped packages, v1 vs v3, dev deps, invalid JSON
- [x] pypi: empty, comments-only, version operators, extras, inline comments, options, markers, bare names
- [x] init integration: repo with `.github/workflows/` + `package-lock.json` + `requirements.txt`
- [x] All 119 existing tests still pass (130 total now)

### Other

- [ ] Full end-to-end test on a real repo (init → check → scope)
- [ ] Integration test: detect PYPI_TOKEN violation via platform profile
- [ ] Landing page: verify CLI version auto-displays on scg.data-insights.ai after release

## Next

- [ ] CI pipeline: auto-build + upload on tag push (eliminate manual scp)
- [ ] GitHub Action published to GitHub Marketplace
- [ ] Homebrew tap formula

## Notes

- Resolution goes through platform API (`/v1/resolve/{ecosystem}/{ref}`), not local resolvers
- `ToolEntry.Ecosystem` in manifest already supports `"npm"` and `"pypi"` values
- `WorkflowParser.Supports()` checks for `.github/workflows/` in path — don't change this
- Resolver package has `npm.go` and `pypi.go` but they're used by platform, not CLI directly
